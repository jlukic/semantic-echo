// wt-rust: the non-quic-go rung.
//
// wtransport 0.7.1 over quinn, an entirely separate WebTransport implementation
// from the Go servers next door. Same certificate, same echo shape. A client
// that binds here but refuses the Go rungs has told us the requirement lives in
// quic-go rather than in the protocol.

use std::error::Error;
use std::net::{SocketAddr, ToSocketAddrs};

use wtransport::endpoint::IncomingSession;
use wtransport::{Endpoint, Identity, ServerConfig};

const CERT: &str = "/cert.pem";
const KEY: &str = "/key.pem";

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

    let connection = request.accept().await?;
    println!("rust session  accepted id={:?}", connection.session_id());

    loop {
        tokio::select! {
            stream = connection.accept_bi() => {
                let (mut send, mut recv) = stream?;
                // per-stream task: a peer that opens a stream and stalls must
                // not hold up datagrams or the next stream on the session
                tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut recv, &mut send).await;
                    let _ = send.finish().await;
                });
            }
            dgram = connection.receive_datagram() => {
                let dgram = dgram?;
                connection.send_datagram(dgram.payload())?;
            }
        }
    }
}
