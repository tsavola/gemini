// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gemini

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
)
func Dial(u *url.URL) (net.Conn, error) {
	if u.Scheme != "gemini" {
		return nil, fmt.Errorf("unsupported protocol: %q", u.Scheme)
	}

	if u.Path == "" {
		u.Path = "/"
	}
	reqURL := u.String()

	if port := u.Port(); port == "" {
		port = "1965"
		u.Host = fmt.Sprintf("%s:%s", u.Hostname(), port)
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}

	var ok bool

	c, err := tls.Dial("tcp", u.Host, config)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			c.Close()
		}
	}()

	if _, err := fmt.Fprintf(c, "%s\r\n", reqURL); err != nil {
		return nil, err
	}

	ok = true
	return c, nil
}
