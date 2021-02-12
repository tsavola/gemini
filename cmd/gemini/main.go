// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/tsavola/gemini"
)

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: %s url\n", flag.CommandLine.Name())
		os.Exit(2)
	}

	if err := Main(flag.Arg(0)); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func Main(uri string) error {
	if !strings.Contains(uri, "://") {
		uri = "gemini://" + uri
	}

	u, err := url.Parse(uri)
	if err != nil {
		return err
	}

	conn, err := gemini.Dial(u)
	if err != nil {
		return err
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	if _, err := io.Copy(os.Stdout, conn); err != nil {
		return err
	}

	err = conn.Close()
	conn = nil
	return err
}
