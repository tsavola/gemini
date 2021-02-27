// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gemini

import (
	"bufio"
	"crypto/tls"
	"log"
	"net"
	"net/url"
	"strings"
	"time"
)

type ServerConn struct {
	raw net.Conn // nil after closing.
	tls *tls.Conn
}

// Close uncleanly.  Finish must not be called after this.
func (c *ServerConn) Close() error {
	if c.raw == nil {
		return nil
	}
	c.raw = nil
	return c.raw.Close()
}

// CloseWrite uncleanly.  Finish must not be called after this.
func (c *ServerConn) CloseWrite() error {
	if c.raw == nil {
		return nil
	}
	c.raw = nil
	return c.raw.Close()
}

func (c *ServerConn) ConnectionState() tls.ConnectionState {
	return c.tls.ConnectionState()
}

// Finish writing cleanly.  Close can be called after this.
func (c *ServerConn) Finish() error {
	if c.raw == nil {
		panic("already closed")
	}
	c.raw = nil
	return c.tls.Close()
}

func (c *ServerConn) LocalAddr() net.Addr {
	return c.tls.LocalAddr()
}

func (c *ServerConn) RemoteAddr() net.Addr {
	return c.tls.RemoteAddr()
}

func (c *ServerConn) SetDeadline(t time.Time) error {
	return c.tls.SetWriteDeadline(t)
}

func (c *ServerConn) SetWriteDeadline(t time.Time) error {
	return c.tls.SetWriteDeadline(t)
}

func (c *ServerConn) VerifyHostname(host string) error {
	return c.tls.VerifyHostname(host)
}

func (c *ServerConn) Write(b []byte) (int, error) {
	return c.tls.Write(b)
}

type ResponseWriter struct {
	conn     WriteFinisher
	headDone bool
	headErr  error
}

func NewResponseWriter(conn WriteFinisher) *ResponseWriter {
	return &ResponseWriter{conn: conn}
}

func (w *ResponseWriter) WriteHeader(h ResponseHeader) {
	if w.headDone {
		panic("header already written")
	}
	w.headDone = true
	_, w.headErr = w.conn.Write(h.Bytes())
}

func (w *ResponseWriter) Write(b []byte) (int, error) {
	if !w.headDone {
		w.WriteHeader(Success("text/gemini"))
	}
	if w.headErr != nil {
		return 0, w.headErr
	}
	return w.conn.Write(b)
}

// Finish writing cleanly.  The underlying connection's Close method can still
// be called after this.
func (w *ResponseWriter) Finish() error {
	if !w.headDone {
		w.WriteHeader(Success("text/gemini"))
	}
	if w.headErr != nil {
		return w.headErr
	}
	return w.conn.Finish()
}

type HandleFunc func(*ServerConn, *url.URL)

func Listen(l net.Listener, config *tls.Config, f HandleFunc) error {
	config = initTLSConfig(config)

	for {
		if err := accept(l, config, f); err != nil {
			return err
		}
	}
}

func accept(l net.Listener, config *tls.Config, f HandleFunc) error {
	rawConn, err := l.Accept()
	if err != nil {
		return err
	}
	defer func() {
		if rawConn != nil {
			rawConn.Close()
		}
	}()

	myConn, u, err := Server(rawConn, config)
	if err != nil {
		log.Printf("%v: %v", rawConn.RemoteAddr(), err)
		return nil
	}

	f(myConn, u)
	rawConn = nil
	return nil
}

func Server(rawConn net.Conn, config *tls.Config) (*ServerConn, *url.URL, error) {
	tlsConn := tls.Server(rawConn, config)
	r := bufio.NewReader(tlsConn)

	line, err := r.ReadString('\n')
	if err != nil {
		return nil, nil, err
	}
	line = line[:len(line)-1]
	if strings.HasSuffix(line, "\r") {
		line = line[:len(line)-1]
	}

	u, err := url.Parse(line)
	if err != nil {
		return nil, u, err
	}

	return &ServerConn{raw: rawConn, tls: tlsConn}, u, nil
}
