/*
Copyright 2017 Rohith Jayawardene All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

// encodeCertificateRequest is responsible for encoding the CSR
func encodeCertificateRequest(csrBytes []byte) (string, error) {
	var encodedCSR bytes.Buffer

	// @step: encode the certificate request
	if err := pem.Encode(&encodedCSR, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}); err != nil {
		return "", err
	}

	return encodedCSR.String(), nil
}

// createCertificateRequest is responsible for making a certificates from options
func createCertificateRequest(c *Config) (*rsa.PrivateKey, []byte, error) {
	// @step: we generate a private key
	private, err := makePrivateKey(c.PrivateKeyFile(), c.Size)
	if err != nil {
		return nil, []byte{}, err
	}

	var writer bytes.Buffer
	// encode the private key to PEM format
	if err = pem.Encode(&writer, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(private),
	}); err != nil {
		return nil, []byte{}, err
	}

	// @step: write the private key to file
	file, err := os.OpenFile(c.PrivateKeyFile(), os.O_TRUNC|os.O_CREATE|os.O_RDWR, os.FileMode(0600))
	if err != nil {
		return nil, []byte{}, err
	}
	defer file.Close()

	if _, err = file.WriteString(writer.String()); err != nil {
		return nil, []byte{}, err
	}

	// @step: creating a CSR from the configuration
	cert := x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA512WithRSA,
		Subject: pkix.Name{
			CommonName:   c.Domains[0],
			Country:      []string{c.Country},
			Province:     []string{c.Province},
			Locality:     []string{c.Locality},
			Organization: []string{c.Organization},
		},
	}

	// @step: iterate the domains and place in the correct fields
	for _, d := range c.Domains {
		ip := net.ParseIP(d)
		if ip.To4() != nil || ip.To16() != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
			continue
		}
		cert.DNSNames = append(cert.DNSNames, d)
	}

	// @step: generate the CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, &cert, private)
	if err != nil {
		return nil, []byte{}, err
	}

	return private, csr, nil
}

// makePrivateKey is responsible for generating a private key or reading in the current one
func makePrivateKey(filename string, size int) (*rsa.PrivateKey, error) {
	_, err := os.Stat(filename)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	// @step: if the file was found, lets attempt to read it in
	if err == nil {
		log.WithFields(log.Fields{
			"path": filename,
		}).Info("loading private key from disk")

		return readPrivateKeyFile(filename)
	}

	log.WithFields(log.Fields{
		"path": filename,
	}).Info("generating private key for certificate")

	return rsa.GenerateKey(rand.Reader, size)
}

// readPrivateKeyFile is responsible for loading the private key in pem format
func readPrivateKeyFile(filename string) (*rsa.PrivateKey, error) {
	// @step: the private key already exists, lets load it
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(content)
	if block == nil {
		return nil, errors.New("unable to decode private from pem file")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

// makeOperationTimeout is responsible for making a kill timer
func makeOperationTimeout(timeout time.Duration) chan interface{} {
	log.Infof("setting a operational timeout of %s", timeout.String())

	doneCh := make(chan interface{}, 0)
	timer := time.NewTimer(timeout)

	go func() {
		select {
		case <-timer.C:
			log.WithFields(log.Fields{
				"error":   "operation timeout",
				"timeout": timeout.String(),
			}).Error("certificate request timed out")

			os.Exit(1)

		case <-doneCh:
			return
		}
	}()

	return doneCh
}

// createHTTPClient creates and returns a api client for cfssl
func createHTTPClient(o *Config) (*http.Client, error) {
	tlsConfig := &tls.Config{}

	// @step: build the tls configuration
	if o.TLSCAPath != "" {
		caCert, err := ioutil.ReadFile(o.TLSCAPath)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	// @step: create the http client
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				KeepAlive: 10 * time.Second,
				Timeout:   10 * time.Second,
			}).DialContext,
			ExpectContinueTimeout: 1 * time.Second,
			IdleConnTimeout:       10 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
		},
	}

	return client, nil
}
