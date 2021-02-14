// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/tsavola/gemini"
)

var tlsConfig = &tls.Config{
	InsecureSkipVerify: true,
}

var isTerm *bool

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s url\n", flag.CommandLine.Name())
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		os.Exit(2)
	}

	url := flag.Arg(0)
	if !strings.Contains(url, "://") {
		url = "gemini://" + url
	}

	for {
		header, err := do(url)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
		}

		if !header.Redirect() {
			code := 1
			if err == nil && header.Success() {
				code = 0
			}
			os.Exit(code)
		}

		url = header.Meta
	}
}

func do(url string) (gemini.ResponseHeader, error) {
	conn, header, err := gemini.Dial(context.Background(), url, tlsConfig)
	if err != nil {
		return header, err
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	if !(header.Success() || header.Redirect()) {
		s := header.Meta
		if s == "" {
			s = header.Status.String()
		}

		switch {
		case header.Status == gemini.StatusSlowDown:
			if n, err := strconv.ParseUint(header.Meta, 10, 64); err == nil {
				if n == 1 {
					s = fmt.Sprintf("%s (1 second)", s)
				} else {
					s = fmt.Sprintf("%s (%d seconds)", s, n)
				}
			}
		}

		fmt.Fprintln(os.Stderr, "status:", s)
	}

	if _, err := io.Copy(os.Stdout, conn); err != nil {
		return header, err
	}

	err = conn.Close()
	conn = nil
	return header, err
}
