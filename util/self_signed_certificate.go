// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// Options to SelfSignedCertificate(...)
type Options struct {
	// hostname, default: "localhost"
	Host string
	// valid from date, eg. "Jan 2 15:04:05 2006", default: time.Now()
	ValidFrom string
	// Validity duration, default: 1 year
	ValidFor time.Duration
	// is CA? default: false
	IsCA bool
	// RSA private key length, used if EcdsaCurve is not specified, default: 2048
	RsaBits int
	// Optionally specify one of "P224"/"P256"/"P384"/"P521" or default to RSA
	EcdsaCurve string
}

/*

Generate a self-signed X.509 certificate for a TLS server.


This is an adaptation of crypto/tls/generate_cert.go that can be
used from within Go programs

Example:

	cer, err := SelfSignedCertificate(Options{})

	config := &tls.Config{Certificates: []tls.Certificate{cer}}

*/

func SelfSignedCertificate(opts Options) (tls.Certificate, error) {

	if opts.Host == "" {
		opts.Host = "localhost"
	}

	if opts.ValidFor == 0 {
		opts.ValidFor = 365 * 24 * time.Hour
	}

	if opts.RsaBits == 0 {
		opts.RsaBits = 2048
	}

	var priv interface{}
	var err error
	switch opts.EcdsaCurve {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, opts.RsaBits)
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return tls.Certificate{}, errors.New(fmt.Sprintf("Unrecognized elliptic curve: %q", opts.EcdsaCurve))
	}
	if err != nil {
		return tls.Certificate{}, errors.New(fmt.Sprintf("Failed to generate private key: %s", err))
	}

	var notBefore time.Time
	if len(opts.ValidFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", opts.ValidFrom)
		if err != nil {
			return tls.Certificate{}, errors.New(fmt.Sprintf("Failed to parse creation date: %s\n", err))
		}
	}

	notAfter := notBefore.Add(opts.ValidFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, errors.New(fmt.Sprintf("Failed to generate serial number: %s", err))
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(opts.Host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if opts.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return tls.Certificate{}, errors.New(fmt.Sprintf("Failed to create certificate: %v", err))
	}

	pemBlock, err := pemBlockForKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), pem.EncodeToMemory(pemBlock))

	if err != nil {
		return tls.Certificate{}, errors.New(fmt.Sprintf("Faled to read x509 keypair: %v", err))
	}

	return cert, nil
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) (*pem.Block, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Unable to marshal ECDSA private key: %v", err))
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	default:
		return nil, errors.New(fmt.Sprintf("Unknown private key type: %v", priv))
	}
}
