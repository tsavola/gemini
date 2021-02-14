// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gemini

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ClientConn struct {
	*bufio.Reader
	conn *tls.Conn
}

func (c *ClientConn) Close() error {
	return c.conn.Close()
}

func (c *ClientConn) CloseRead() error {
	return c.conn.Close()
}

func (c *ClientConn) ConnectionState() tls.ConnectionState {
	return c.conn.ConnectionState()
}

func (c *ClientConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *ClientConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *ClientConn) SetDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *ClientConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

type Dialer struct {
	tls.Dialer
	Net            string
	Addr           string
	ReadBufferSize int
}

func Dial(ctx context.Context, url string, c *tls.Config) (*ClientConn, ResponseHeader, error) {
	u, err := parseURL(url)
	if err != nil {
		return nil, ResponseHeader{}, err
	}

	d := Dialer{
		Dialer: tls.Dialer{
			Config: c,
		},
	}

	return d.Dial(ctx, u)
}

func (d *Dialer) Dial(ctx context.Context, u *url.URL) (*ClientConn, ResponseHeader, error) {
	if u.Scheme != "gemini" {
		return nil, ResponseHeader{}, fmt.Errorf("unsupported protocol: %q", u.Scheme)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	reqURL := u.String()

	network := d.Net
	if network == "" {
		network = "tcp"
	}

	addr := d.Addr
	if addr == "" {
		if u.Port() == "" {
			addr = fmt.Sprintf("%s:%d", u.Hostname(), DefaultPort)
		} else {
			addr = u.Host
		}
	}

	tlsDialer := d.Dialer
	tlsDialer.Config = initTLSConfig(tlsDialer.Config)

	var ok bool

	x, err := tlsDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, ResponseHeader{}, err
	}
	tlsConn := x.(*tls.Conn)
	defer func() {
		if !ok {
			tlsConn.Close()
		}
	}()

	if _, err := fmt.Fprintf(tlsConn, "%s\r\n", reqURL); err != nil {
		return nil, ResponseHeader{}, err
	}

	var r *bufio.Reader
	if d.ReadBufferSize == 0 {
		r = bufio.NewReader(tlsConn)
	} else {
		r = bufio.NewReaderSize(tlsConn, d.ReadBufferSize)
	}

	line, err := r.ReadString('\n')
	if err != nil {
		return nil, ResponseHeader{}, err
	}
	if !strings.HasSuffix(line, "\r\n") {
		return nil, ResponseHeader{}, errors.New("invalid response header")
	}
	line = line[:len(line)-2]

	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 {
		return nil, ResponseHeader{}, errors.New("invalid response header")
	}

	n, err := strconv.ParseUint(parts[0], 10, 7)
	if err != nil || n >= 100 {
		return nil, ResponseHeader{}, errors.New("invalid status code")
	}

	ok = true
	return &ClientConn{r, tlsConn}, ResponseHeader{Status(n), parts[1]}, nil
}

// parseURL can be called when the url package is shadowed.
func parseURL(s string) (*url.URL, error) {
	return url.Parse(s)
}
