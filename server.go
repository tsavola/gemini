// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gemini

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
	"time"
)

const DefaultPort = 1965

type WriteFinisher interface {
	io.Writer
	Finish() error
}

type WriteCloseFinisher interface {
	io.WriteCloser
	Finish() error
}

type Conn struct {
	raw net.Conn // nil after closing.
	tls *tls.Conn
}

// Close uncleanly.  Finish must not be called after this.
func (c *Conn) Close() error {
	if c.raw == nil {
		return nil
	}
	c.raw = nil
	return c.raw.Close()
}

// CloseWrite uncleanly.  Finish must not be called after this.
func (c *Conn) CloseWrite() error {
	if c.raw == nil {
		return nil
	}
	c.raw = nil
	return c.raw.Close()
}

func (c *Conn) ConnectionState() tls.ConnectionState {
	return c.tls.ConnectionState()
}

// Finish writing cleanly.  Close can be called after this.
func (c *Conn) Finish() error {
	if c.raw == nil {
		panic("already closed")
	}
	c.raw = nil
	return c.tls.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.tls.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.tls.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.tls.SetWriteDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.tls.SetWriteDeadline(t)
}

func (c *Conn) VerifyHostname(host string) error {
	return c.tls.VerifyHostname(host)
}

func (c *Conn) Write(b []byte) (int, error) {
	return c.tls.Write(b)
}

type ResponseHeader struct {
	Status int
	Meta   string
}

func StatusInput(status int, message string) ResponseHeader {
	if status < 10 || status > 19 {
		panic(status)
	}
	return ResponseHeader{status, message}
}

func StatusSuccess(status int, contentType string) ResponseHeader {
	if status < 20 || status > 29 {
		panic(status)
	}
	return ResponseHeader{status, contentType}
}

func StatusOK(contentType string) ResponseHeader {
	return StatusSuccess(20, contentType)
}

func StatusRedirect(status int, location *url.URL) ResponseHeader {
	if status < 30 || status > 39 {
		panic(status)
	}
	return ResponseHeader{status, location.String()}
}

func StatusTemporaryFailure(status int, message string) ResponseHeader {
	if status < 40 || status > 49 {
		panic(status)
	}
	return ResponseHeader{status, message}
}

var StatusNotFound = ResponseHeader{44, "not found"}

func StatusPermanentFailure(status int, message string) ResponseHeader {
	if status < 50 || status > 59 {
		panic(status)
	}
	return ResponseHeader{status, message}
}

func StatusClientCertificateRequired(status int, message string) ResponseHeader {
	if status < 60 || status > 69 {
		panic(status)
	}
	return ResponseHeader{status, message}
}

func (h ResponseHeader) String() string {
	if h.Status < 0 || h.Status >= 100 {
		panic("invalid status code")
	}
	if strings.Contains(h.Meta, "\n") {
		panic("invalid meta string")
	}
	return fmt.Sprintf("%02d %s\r\n", h.Status, h.Meta)
}

func (h ResponseHeader) Bytes() []byte {
	return []byte(h.String())
}

func (h ResponseHeader) FinishTo(w WriteFinisher) error {
	if _, err := w.Write(h.Bytes()); err != nil {
		return err
	}

	return w.Finish()
}

type ResponseWriter struct {
	conn     WriteCloseFinisher
	headDone bool
	headErr  error
}

func NewResponseWriter(w WriteCloseFinisher) *ResponseWriter {
	return &ResponseWriter{conn: w}
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
		w.WriteHeader(StatusOK("text/gemini"))
	}
	if w.headErr != nil {
		return 0, w.headErr
	}
	return w.conn.Write(b)
}

// Close uncleanly.  Finish must not be called after this.
func (w *ResponseWriter) Close() error {
	return w.conn.Close()
}

// Finish writing cleanly.  Close can be called after this.
func (w *ResponseWriter) Finish() error {
	return w.conn.Finish()
}

type HandleFunc func(*Conn, *url.URL)

func Listen(l net.Listener, config *tls.Config, f HandleFunc) error {
	if config.CipherSuites == nil {
		config.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		}
	}
	if config.MinVersion == 0 {
		config.MinVersion = tls.VersionTLS12
	}

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

func Server(rawConn net.Conn, config *tls.Config) (*Conn, *url.URL, error) {
	tlsConn := tls.Server(rawConn, config)
	r := bufio.NewReader(tlsConn)

	line, err := r.ReadString('\n')
	if err != nil {
		return nil, nil, err
	}
	if !strings.HasSuffix(line, "\r\n") {
		return nil, nil, errors.New("invalid response header")
	}
	uri := line[:len(line)-2]

	u, err := url.Parse(uri)
	if err != nil {
		return nil, u, err
	}

	return &Conn{raw: rawConn, tls: tlsConn}, u, nil
}
