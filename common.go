// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gemini

import (
	"crypto/tls"
	"fmt"
	"io"
	"strings"
	"time"
)

const DefaultPort = 1965

type WriteFinisher interface {
	io.Writer
	Finish() error
}

type Status int

const (
	StatusInput                     Status = 10
	StatusSensitiveInput            Status = 11
	StatusSuccess                   Status = 20
	StatusTemporaryRedirect         Status = 30
	StatusPermanentRedirect         Status = 31
	StatusTemporaryFailure          Status = 40
	StatusServerUnavailable         Status = 41
	StatusCGIError                  Status = 42
	StatusProxyError                Status = 43
	StatusSlowDown                  Status = 44
	StatusPermanentFailure          Status = 50
	StatusNotFound                  Status = 51
	StatusGone                      Status = 52
	StatusProxyRequestRefused       Status = 53
	StatusBadRequest                Status = 59
	StatusClientCertificateRequired Status = 60
	StatusCertificateNotAuthorized  Status = 61
	StatusCertificateNotValid       Status = 62
)

func (s Status) Header() ResponseHeader {
	return ResponseHeader{s, s.String()}
}

func (s Status) Input() bool {
	return s >= 10 && s <= 19
}

func (s Status) Success() bool {
	return s >= 20 && s <= 29
}

func (s Status) Redirect() bool {
	return s >= 30 && s <= 39
}

func (s Status) TemporaryFailure() bool {
	return s >= 40 && s <= 49
}

func (s Status) PermanentFailure() bool {
	return s >= 50 && s <= 59
}

func (s Status) ClientCertificateRequired() bool {
	return s >= 60 && s <= 69
}

func (s Status) String() string {
	switch s {
	case StatusInput:
		return "input"
	case StatusSensitiveInput:
		return "sensitive input"
	case StatusSuccess:
		return "success"
	case StatusTemporaryRedirect:
		return "temporary redirect"
	case StatusPermanentRedirect:
		return "permanent redirect"
	case StatusTemporaryFailure:
		return "temporary failure"
	case StatusServerUnavailable:
		return "server unavailable"
	case StatusCGIError:
		return "CGI error"
	case StatusProxyError:
		return "proxy error"
	case StatusSlowDown:
		return "slow down"
	case StatusPermanentFailure:
		return "permanent failure"
	case StatusNotFound:
		return "not found"
	case StatusGone:
		return "gone"
	case StatusProxyRequestRefused:
		return "proxy request refused"
	case StatusBadRequest:
		return "bad request"
	case StatusClientCertificateRequired:
		return "client certificate required"
	case StatusCertificateNotAuthorized:
		return "certificate not authorized"
	case StatusCertificateNotValid:
		return "certificate not valid"
	default:
		return ""
	}
}

type ResponseHeader struct {
	Status
	Meta string
}

func InputHeader(status Status, message string) ResponseHeader {
	if !status.Input() {
		panic(status)
	}
	return ResponseHeader{status, message}
}

func SuccessHeader(status Status, contentType string) ResponseHeader {
	if !status.Success() {
		panic(status)
	}
	return ResponseHeader{status, contentType}
}

func RedirectHeader(status Status, location string) ResponseHeader {
	if !status.Redirect() {
		panic(status)
	}
	return ResponseHeader{status, location}
}

func TemporaryFailureHeader(status Status, reason string) ResponseHeader {
	if !status.TemporaryFailure() {
		panic(status)
	}
	return ResponseHeader{status, reason}
}

func PermanentFailureHeader(status Status, reason string) ResponseHeader {
	if !status.PermanentFailure() {
		panic(status)
	}
	return ResponseHeader{status, reason}
}

func ClientCertificateRequiredHeader(status Status, reason string) ResponseHeader {
	if !status.ClientCertificateRequired() {
		panic(status)
	}
	return ResponseHeader{status, reason}
}

func Input(message string) ResponseHeader {
	return InputHeader(StatusInput, message)
}

func SensitiveInput(message string) ResponseHeader {
	return InputHeader(StatusSensitiveInput, message)
}

func Success(contentType string) ResponseHeader {
	return SuccessHeader(StatusSuccess, contentType)
}

func TemporaryRedirect(location string) ResponseHeader {
	return RedirectHeader(StatusTemporaryRedirect, location)
}

func PermanentRedirect(location string) ResponseHeader {
	return RedirectHeader(StatusPermanentRedirect, location)
}

func TemporaryFailure(reason string) ResponseHeader {
	return TemporaryFailureHeader(StatusTemporaryFailure, reason)
}

func ServerUnavailable() ResponseHeader {
	return StatusServerUnavailable.Header()
}

func CGIError() ResponseHeader {
	return StatusCGIError.Header()
}

func ProxyError() ResponseHeader {
	return StatusProxyError.Header()
}

func SlowDown(wait time.Duration) ResponseHeader {
	s := wait / time.Second
	if s < 1 {
		s = 1
	}
	return TemporaryFailureHeader(44, fmt.Sprintf("%d", s))
}

func PermanentFailure(reason string) ResponseHeader {
	return PermanentFailureHeader(50, reason)
}

func NotFound() ResponseHeader {
	return StatusNotFound.Header()
}

func Gone() ResponseHeader {
	return StatusGone.Header()
}

func ProxyRequestRefused() ResponseHeader {
	return StatusProxyRequestRefused.Header()
}

func BadRequest() ResponseHeader {
	return StatusBadRequest.Header()
}

func ClientCertificateRequired() ResponseHeader {
	return StatusClientCertificateRequired.Header()
}

func CertificateNotAuthorized() ResponseHeader {
	return StatusCertificateNotAuthorized.Header()
}

func CertificateNotValid() ResponseHeader {
	return StatusCertificateNotValid.Header()
}

// Header overrides the corresponding Status method.
func (h ResponseHeader) Header() ResponseHeader {
	return h
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

var (
	DefaultCipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	DefaultMinTLSVersion uint16 = tls.VersionTLS12
)

func initTLSConfig(c *tls.Config) *tls.Config {
	if c == nil {
		c = new(tls.Config)
	} else {
		c = c.Clone()
	}

	if c.CipherSuites == nil {
		c.CipherSuites = DefaultCipherSuites
	}
	if c.MinVersion == 0 {
		c.MinVersion = DefaultMinTLSVersion
	}

	return c
}
