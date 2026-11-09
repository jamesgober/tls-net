// Command tlspeer is the Go side of tls-net's interop tests (tests/go.rs):
// a client or a server on crypto/tls, standard library only.
//
//	tlspeer client -addr A -name N -ca F [-alpn h2,http/1.1] [-cert F -key F] [-max 1.2] [-conns N]
//	tlspeer server -cert F -key F [-clientca F] [-alpn h2,http/1.1] [-max 1.2]
//
// The client makes -conns connections with one session cache, sends an
// HTTP/1.1 request on each, and prints one line per connection:
// "conn=1 version=TLS1.3 alpn=h2 resumed=false reply=<first line>".
// The server prints "listening <addr>", then answers each connection's first
// line with "version=.. alpn=.. client=<first DNS name or none> resumed=..".
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: tlspeer client|server [flags]")
	}
	switch os.Args[1] {
	case "client":
		client(os.Args[2:])
	case "server":
		server(os.Args[2:])
	default:
		fail("unknown mode " + os.Args[1])
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}

func pool(path string) *x509.CertPool {
	pem, err := os.ReadFile(path)
	if err != nil {
		fail(err.Error())
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(pem) {
		fail("no certificates in " + path)
	}
	return p
}

func base(alpn, max, cert, key string) *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if alpn != "" {
		c.NextProtos = strings.Split(alpn, ",")
	}
	switch max {
	case "", "1.3":
	case "1.2":
		c.MaxVersion = tls.VersionTLS12
	default:
		fail("-max is 1.2 or 1.3")
	}
	if cert != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			fail(err.Error())
		}
		c.Certificates = []tls.Certificate{pair}
	}
	return c
}

func version(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	}
	return fmt.Sprintf("0x%04x", v)
}

func client(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	addr := fs.String("addr", "", "host:port")
	name := fs.String("name", "localhost", "server name to send and verify")
	ca := fs.String("ca", "", "trusted CA (PEM)")
	alpn := fs.String("alpn", "", "ALPN protocols, comma-separated")
	cert := fs.String("cert", "", "client certificate chain (PEM)")
	key := fs.String("key", "", "client key (PEM)")
	max := fs.String("max", "", "highest version: 1.2 or 1.3")
	conns := fs.Int("conns", 1, "connections, sharing one session cache")
	_ = fs.Parse(args)
	c := base(*alpn, *max, *cert, *key)
	c.ServerName = *name
	c.RootCAs = pool(*ca)
	c.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	for i := 1; i <= *conns; i++ {
		conn, err := tls.Dial("tcp", *addr, c)
		if err != nil {
			fmt.Printf("conn=%d error=%q\n", i, err.Error())
			os.Exit(1)
		}
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", *name)
		body, err := io.ReadAll(conn)
		st := conn.ConnectionState()
		conn.Close()
		if err != nil {
			fmt.Printf("conn=%d error=%q\n", i, err.Error())
			os.Exit(1)
		}
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		fmt.Printf("conn=%d version=%s alpn=%s resumed=%v reply=%s\n", i,
			version(st.Version), st.NegotiatedProtocol, st.DidResume,
			strings.TrimSpace(lines[len(lines)-1]))
	}
}

func server(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	cert := fs.String("cert", "", "certificate chain (PEM)")
	key := fs.String("key", "", "key (PEM)")
	clientca := fs.String("clientca", "", "require client certificates from this CA (PEM)")
	alpn := fs.String("alpn", "", "ALPN protocols, comma-separated")
	max := fs.String("max", "", "highest version: 1.2 or 1.3")
	_ = fs.Parse(args)
	c := base(*alpn, *max, *cert, *key)
	if *clientca != "" {
		c.ClientCAs = pool(*clientca)
		c.ClientAuth = tls.RequireAndVerifyClientCert
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", c)
	if err != nil {
		fail(err.Error())
	}
	fmt.Printf("listening %s\n", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			fail(err.Error())
		}
		go answer(conn.(*tls.Conn))
	}
}

func answer(conn *tls.Conn) {
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection: %v\n", err)
		return
	}
	st := conn.ConnectionState()
	who := "none"
	if len(st.PeerCertificates) > 0 && len(st.PeerCertificates[0].DNSNames) > 0 {
		who = st.PeerCertificates[0].DNSNames[0]
	}
	fmt.Fprintf(conn, "version=%s alpn=%s client=%s resumed=%v echo=%s\n",
		version(st.Version), st.NegotiatedProtocol, who, st.DidResume, strings.TrimSpace(line))
}
