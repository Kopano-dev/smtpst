/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

const (
	certStoreFn    = "certificate.x509"
	certTmpStoreFn = "certificate.x509.tmp"
)

// loadCertificate attempts to load an x509 certificate from a file. If the file
// does not exist, it tries to generate a new one and save it to a file.
func (server *Server) loadCertificate() (tls.Certificate, error) {
	logger := server.logger

	var certificate tls.Certificate
	var err error

	pemFile := filepath.Join(server.config.StatePath, certStoreFn)
	certificate, err = tls.LoadX509KeyPair(pemFile, pemFile)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Debugln("client certificate not found, generating")
			certificate, err = server.generateCertificate()
			if err != nil {
				return certificate, fmt.Errorf("failed to generate new certificate: %w", err)
			}
			logger.Infoln("created new client certificate")
		} else {
			return certificate, fmt.Errorf("failed to load client certificate from file: %w", err)
		}
	} else {
		logger.Debugln("loaded client certificate from file")
	}

	return certificate, nil
}

// generateCertificate attempts to generate an x509 certificate and save it,
// along with the private key, to a file in PEM format.
func (server *Server) generateCertificate() (tls.Certificate, error) {
	var certificate tls.Certificate

	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return certificate, err
	}

	// Create a random 64 bit number
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(64), nil).Sub(max, big.NewInt(1))
	sn, err := rand.Int(rand.Reader, max)

	if err != nil {
		return certificate, err
	}
	template := &x509.Certificate{
		SerialNumber: sn,
	}

	certDER, err := x509.CreateCertificate(nil, template, template, pubKey, privKey)
	if err != nil {
		return certificate, err
	}
	privKeyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return certificate, err
	}

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	privKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyDER,
	}

	certTmpFn := filepath.Join(server.config.StatePath, certTmpStoreFn)
	certTmpStoreFn, err := os.Create(certTmpFn)
	if err != nil {
		return certificate, err
	}

	certPEM := pem.EncodeToMemory(certBlock)
	privKeyPEM := pem.EncodeToMemory(privKeyBlock)

	_, err = certTmpStoreFn.Write(certPEM)
	if err != nil {
		return certificate, err
	}
	_, err = certTmpStoreFn.Write(privKeyPEM)
	if err != nil {
		return certificate, err
	}

	certificate, err = tls.X509KeyPair(certPEM, privKeyPEM)
	if err != nil {
		return certificate, err
	}

	certTmpStoreFn.Close()
	err = os.Rename(certTmpFn, filepath.Join(server.config.StatePath, certStoreFn))
	if err != nil {
		os.Remove(certTmpFn)
		return certificate, err
	}

	return certificate, err
}
