// wt-rust: the non-quic-go rung.
//
// wtransport 0.7.1 over quinn, an entirely separate WebTransport implementation
// from the Go servers next door. Same certificate, same echo shape. A client
// that binds here but refuses the Go rungs has told us the requirement lives in
// quic-go rather than in the protocol.

use std::collections::HashMap;
use std::error::Error;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use wtransport::endpoint::{IncomingSession, SessionRequest};
use wtransport::{Endpoint, Identity, RecvStream, SendStream, ServerConfig, VarInt};

const CERT: &str = "/cert.pem";
const KEY: &str = "/key.pem";

// egress is the only unbounded axis on a public echo, so a session carries a
// byte budget and a deadline, one address may hold only a few at once, and the
// process stops echoing entirely past a daily ceiling. same numbers as the Go
// rungs, sized far above honest use
const SESSION_ECHO_BUDGET: u64 = 1 << 20;
const SESSION_LIFETIME: Duration = Duration::from_secs(120);
const PER_ADDRESS_SESSIONS: usize = 4;
const DAILY_EGRESS_CEILING: u64 = 2 << 30;
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

struct Budgets {
    sessions: HashMap<IpAddr, usize>,
    echoed: u64,
    window: Instant,
    warned: bool,
}

static LIMITS: LazyLock<Mutex<Budgets>> = LazyLock::new(|| {
    Mutex::new(Budgets {
        sessions: HashMap::new(),
        echoed: 0,
        window: Instant::now(),
        warned: false,
    })
});

// the window restarts 24h after it opened, which is all a bill guard needs
fn roll(state: &mut Budgets) {
    if state.window.elapsed() >= DAY {
        state.echoed = 0;
        state.window = Instant::now();
        state.warned = false;
    }
}

fn acquire(address: IpAddr) -> Result<(), &'static str> {
    let mut state = LIMITS.lock().unwrap();
    roll(&mut state);
    if state.echoed >= DAILY_EGRESS_CEILING {
        return Err("daily egress ceiling");
    }
    let held = state.sessions.entry(address).or_insert(0);
    if *held >= PER_ADDRESS_SESSIONS {
        return Err("per-address session cap");
    }
    *held += 1;
    Ok(())
}

fn release(address: IpAddr) {
    let mut state = LIMITS.lock().unwrap();
    if let Some(held) = state.sessions.get_mut(&address) {
        *held -= 1;
        if *held == 0 {
            state.sessions.remove(&address);
        }
    }
}

// reports whether the process may keep echoing once n more bytes are counted
fn spend_global(n: u64) -> bool {
    let mut state = LIMITS.lock().unwrap();
    roll(&mut state);
    state.echoed += n;
    if state.echoed < DAILY_EGRESS_CEILING {
        return true;
    }
    if !state.warned {
        state.warned = true;
        println!(
            "rust EGRESS CEILING: {} bytes echoed in 24h, refusing new sessions and halting echo",
            state.echoed
        );
    }
    false
}

// charges n bytes against the session budget and the process ceiling, naming
// whichever one refused
fn charge(echoed: &AtomicU64, n: u64) -> Result<(), &'static str> {
    if echoed.fetch_add(n, Ordering::Relaxed) + n > SESSION_ECHO_BUDGET {
        return Err("echo budget reached");
    }
    if !spend_global(n) {
        return Err("daily egress ceiling reached");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_default();
    let port: u16 = args.next().unwrap_or_default().parse().unwrap_or(4438);

    let bind = resolve(&host, port)?;
    let identity = Identity::load_pemfiles(CERT, KEY).await?;

    let config = ServerConfig::builder()
        .with_bind_address(bind)
        .with_identity(identity)
        .build();

    let server = Endpoint::server(config)?;
    println!("rust boot wt={bind} wtransport=0.7.1");

    loop {
        let incoming = server.accept().await;
        tokio::spawn(handle(incoming));
    }
}

// wtransport binds a SocketAddr, but Fly hands out public UDP on a named
// interface, so the name has to be resolved before the endpoint opens
fn resolve(host: &str, port: u16) -> Result<SocketAddr, Box<dyn Error>> {
    if host.is_empty() {
        return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
    }
    (host, port)
        .to_socket_addrs()?
        .find(|addr| addr.is_ipv4())
        .ok_or_else(|| format!("rust: no ipv4 address for {host}").into())
}

async fn handle(incoming: IncomingSession) {
    if let Err(err) = serve(incoming).await {
        println!("rust session ended: {err}");
    }
}

async fn serve(incoming: IncomingSession) -> Result<(), Box<dyn Error>> {
    let request = incoming.await?;
    println!(
        "rust connect  authority={:?} path={:?}",
        request.authority(),
        request.path()
    );

    if request.path() != "/echo" {
        request.not_found().await;
        return Ok(());
    }

    let address = request.remote_address().ip();
    if let Err(why) = acquire(address) {
        println!("rust session declined remote={address} ({why})");
        request.forbidden().await;
        return Ok(());
    }

    // the slot is held from here, so every exit below runs through release
    let result = echo_session(request).await;
    release(address);
    result
}

async fn echo_session(request: SessionRequest) -> Result<(), Box<dyn Error>> {
    let connection = request.accept().await?;
    println!("rust session  accepted id={:?}", connection.session_id());

    // both directions share one budget, and whichever limit bites first closes
    // the session with a readable reason
    let echoed = Arc::new(AtomicU64::new(0));
    let deadline = tokio::time::sleep(SESSION_LIFETIME);
    tokio::pin!(deadline);
    // stream echoes run on their own tasks, so they report a spent budget back
    // here rather than quietly stopping and leaving the session idle
    let (stop, mut stopped) = tokio::sync::mpsc::channel::<&'static str>(1);

    let outcome: Option<&str> = loop {
        tokio::select! {
            _ = &mut deadline => break Some("session lifetime reached"),
            Some(why) = stopped.recv() => break Some(why),
            stream = connection.accept_bi() => {
                let (mut send, mut recv) = match stream {
                    Ok(stream) => stream,
                    Err(_) => break None,
                };
                // per-stream task: a peer that opens a stream and stalls must
                // not hold up datagrams or the next stream on the session
                let echoed = Arc::clone(&echoed);
                let stop = stop.clone();
                tokio::spawn(async move {
                    if let Err(why) = echo_stream(&mut recv, &mut send, &echoed).await {
                        let _ = stop.try_send(why);
                    }
                    let _ = send.finish().await;
                });
            }
            dgram = connection.receive_datagram() => {
                let dgram = match dgram {
                    Ok(dgram) => dgram,
                    Err(_) => break None,
                };
                let payload = dgram.payload();
                if let Err(why) = charge(&echoed, payload.len() as u64) {
                    break Some(why);
                }
                if connection.send_datagram(payload).is_err() {
                    break None;
                }
            }
        }
    };

    if let Some(why) = outcome {
        println!("rust session  closing id={:?} ({why})", connection.session_id());
        connection.close(VarInt::from_u32(0), why.as_bytes());
    }
    Ok(())
}

// Ok means the stream ended on its own; Err names the budget that stopped it
async fn echo_stream(
    recv: &mut RecvStream,
    send: &mut SendStream,
    echoed: &AtomicU64,
) -> Result<(), &'static str> {
    let mut buffer = vec![0u8; 32 * 1024];
    loop {
        let read = match recv.read(&mut buffer).await {
            Ok(Some(read)) if read > 0 => read,
            _ => return Ok(()),
        };
        charge(echoed, read as u64)?;
        if send.write_all(&buffer[..read]).await.is_err() {
            return Ok(());
        }
    }
}
