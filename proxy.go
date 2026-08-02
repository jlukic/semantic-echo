// Fly's TCP service is raw passthrough, so the page server's view of a client
// is Fly's own proxy while the UDP listeners see the client itself. The two
// never agree, which leaves the observation lookup unable to find the session
// it was asked about. The PROXY protocol carries the original address across
// that hop.
//
// The reader is deliberately tolerant: a connection that arrives without a
// header is passed through untouched, so the same binary runs locally with no
// proxy in front and on Fly with `handlers = ["proxy_proto"]` set.
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	proxyV2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")
	proxyV1Prefix    = []byte("PROXY ")
)

type proxyListener struct{ net.Listener }

func (l proxyListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newProxyConn(conn), nil
}

// proxyConn reads through a buffer, because deciding whether a header is
// present means looking at bytes that belong to the stream if it is not
type proxyConn struct {
	net.Conn
	reader *bufio.Reader
	remote net.Addr
}

func newProxyConn(conn net.Conn) *proxyConn {
	wrapped := &proxyConn{Conn: conn, reader: bufio.NewReader(conn)}
	// a client that connects and says nothing must not hold the accept loop
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if address, err := readProxyHeader(wrapped.reader); err == nil {
		wrapped.remote = address
	}
	conn.SetReadDeadline(time.Time{})
	return wrapped
}

func (c *proxyConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func (c *proxyConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}

var errNoProxyHeader = errors.New("no proxy protocol header")

// readProxyHeader consumes a PROXY header if one is there and reports the
// source address it carries. It consumes nothing when there is no header.
func readProxyHeader(reader *bufio.Reader) (net.Addr, error) {
	prefix, err := reader.Peek(len(proxyV2Signature))
	if err != nil {
		return nil, errNoProxyHeader
	}
	if string(prefix) == string(proxyV2Signature) {
		return readProxyV2(reader)
	}
	if string(prefix[:len(proxyV1Prefix)]) == string(proxyV1Prefix) {
		return readProxyV1(reader)
	}
	return nil, errNoProxyHeader
}

// v1 is a single text line: PROXY TCP4 <src> <dst> <sport> <dport>\r\n
func readProxyV1(reader *bufio.Reader) (net.Addr, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, errNoProxyHeader
	}
	fields := strings.Fields(strings.TrimRight(line, "\r\n"))
	if len(fields) < 6 {
		return nil, errNoProxyHeader
	}
	port, err := strconv.Atoi(fields[4])
	if err != nil {
		return nil, errNoProxyHeader
	}
	ip := net.ParseIP(fields[2])
	if ip == nil {
		return nil, errNoProxyHeader
	}
	return &net.TCPAddr{IP: ip, Port: port}, nil
}

// v2 is the 16-byte signature block followed by an address block whose length
// the block itself declares
func readProxyV2(reader *bufio.Reader) (net.Addr, error) {
	header := make([]byte, 16)
	if _, err := readFull(reader, header); err != nil {
		return nil, errNoProxyHeader
	}
	length := int(binary.BigEndian.Uint16(header[14:16]))
	body := make([]byte, length)
	if _, err := readFull(reader, body); err != nil {
		return nil, errNoProxyHeader
	}

	// high nibble 0x2 is PROXY; 0x0 is LOCAL, a health check with no address
	if header[12]>>4 != 0x2 || header[12]&0x0f != 0x1 {
		return nil, errNoProxyHeader
	}

	switch header[13] {
	case 0x11: // TCP over IPv4
		if len(body) < 12 {
			return nil, errNoProxyHeader
		}
		return &net.TCPAddr{IP: net.IP(body[0:4]), Port: int(binary.BigEndian.Uint16(body[8:10]))}, nil
	case 0x21: // TCP over IPv6
		if len(body) < 36 {
			return nil, errNoProxyHeader
		}
		return &net.TCPAddr{IP: net.IP(body[0:16]), Port: int(binary.BigEndian.Uint16(body[32:34]))}, nil
	}
	return nil, errNoProxyHeader
}

func readFull(reader *bufio.Reader, buffer []byte) (int, error) {
	read := 0
	for read < len(buffer) {
		n, err := reader.Read(buffer[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}
