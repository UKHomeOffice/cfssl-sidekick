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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jpillora/backoff"
	log "github.com/sirupsen/logrus"
)

type controller struct {
	config *Config
	// client is the api client to cfssl
	client *http.Client
}

// newController creates and returns a new cfssl controller
func newController(c Config) (*controller, error) {
	// @step: validate the configuration
	if err := c.IsValid(); err != nil {
		return nil, err
	}
	if c.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	log.SetFormatter(&log.JSONFormatter{})

	// create the http client
	client, err := createHTTPClient(&c)
	if err != nil {
		return nil, err
	}

	return &controller{config: &c, client: client}, nil
}

// run is responsible for the main service loop
func (c *controller) run() error {
	// @step: lets ensure the certificate directory is there
	if err := os.MkdirAll(c.config.CertsDir, os.FileMode(0770)); err != nil {
		return fmt.Errorf("failed to ensure certficate directory: %s", err)
	}

	// @step: we generate the certificate request - we first need to check if a key already exists
	log.WithFields(log.Fields{
		"hostnames": c.config.Domains,
	}).Debug("creating certificate request")

	_, csr, err := createCertificateRequest(c.config)
	if err != nil {
		return fmt.Errorf("failed to generate csr: %s", err)
	}

	log.WithFields(log.Fields{
		"hostnames": c.config.Domains,
	}).Debug("encoding the certificate request into a CSR")

	// @step: encode the CSR into the pem block
	encoded, err := encodeCertificateRequest(csr)
	if err != nil {
		return fmt.Errorf("failed to encode csr: %s", err)
	}

	// @step: create a backoff with jitter
	jitter := &backoff.Backoff{Min: 5 * time.Second, Max: 60 * time.Second, Jitter: true, Factor: 1.2}
	firstrun := true

	for {
		err := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
			defer cancel()

			return c.handleCertificateRequest(ctx, encoded)
		}()
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("failed to proccess certificate request")
			if c.config.Onetime || firstrun {
				os.Exit(1)
			}
			// @logic we ONLY retry second run i.e we've already acquired a certficate we're trying to renew
			time.Sleep(jitter.Duration())

			continue
		}
		firstrun = false
		// @step: we can reset the backoff
		jitter.Reset()

		if c.config.Onetime {
			os.Exit(0)
		}

		// @step: we've successfully acquired a certificate lets wait for the expiration
		log.WithFields(log.Fields{
			"expiration": c.config.Expiry.String(),
		}).Info("sleeping until the next iteration")

		time.Sleep(c.config.Expiry)
	}
}

// handleCertificateRequest is responsible for wrapper a certificate signing request
func (c *controller) handleCertificateRequest(ctx context.Context, encoded string) error {
	doneCh := make(chan error, 0)
	bucket := make(chan struct{}, 1)
	defer close(bucket)

	go func() {
		// @logic as long as we have a token to operate continue
		for range bucket {
			doneCh <- c.doCertificateRequest(encoded)
		}
	}()

	// @step: add a single token into the bucket
	bucket <- struct{}{}
	// @step: create a backoff for failed attempts
	jitter := &backoff.Backoff{Min: 3 * time.Second, Max: 10 * time.Second, Jitter: true, Factor: 1.2}
	for {
		// @step: wait for a timeout of a result from the request
		select {
		case <-ctx.Done():
			return errors.New("operation has timed out or been canceled")
		case err := <-doneCh:
			if err == nil {
				return nil
			}
			log.WithFields(log.Fields{"error": err.Error()}).Error("unable to process certificate request")
		}
		// @step: wait for a period of time and retry
		time.Sleep(jitter.Duration())
		// @step: add a token to operate
		bucket <- struct{}{}
	}
}

// doCertificateRequest is responsible for attempting to request a certficate
func (c *controller) doCertificateRequest(encoded string) error {
	log.WithFields(log.Fields{
		"domains":  strings.Join(c.config.Domains, ","),
		"endpoint": c.config.EndpointURL,
		"expiry":   c.config.Expiry.String(),
		"profile":  c.config.EndpointProfile,
	}).Info("attempting to acquire certificate from ceritificate authority")

	err := func() error {
		response, err := c.doSigningRequest(&SigningRequest{
			Bundle:             true,
			CertificateRequest: encoded,
			Profile:            c.config.EndpointProfile,
		})
		if err != nil {
			return err
		}
		if err := c.handleCertificateResponse(response); err != nil {
			return err
		}
		log.WithFields(log.Fields{
			"certificate": c.config.CertificateFile(),
			"private_key": c.config.PrivateKeyFile(),
		}).Info("successfully wrote the tls certificate")

		return nil
	}()

	return err
}

// handleCertificateResponse is responsible for handling the certificate response
func (c *controller) handleCertificateResponse(response *SigningResponse) error {
	// @check the response was successful
	if !response.Success {
		return fmt.Errorf("unsuccessful operation, errors: %s", response.Errors[0].Message)
	}

	// @check we have a certificate
	if response.Result.Certificate == "" {
		return errors.New("no certificate found in the response")
	}

	log.WithFields(log.Fields{
		"path": c.config.CertificateFile(),
	}).Info("writing the certificate to disk")

	content := response.Result.Certificate
	if response.Result.Bundle.Bundle != "" {
		content = response.Result.Bundle.Bundle
	}

	file, err := os.OpenFile(c.config.CertificateFile(), os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(0600))
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err = file.WriteString(content); err != nil {
		return err
	}

	// @step: do we need to call an external updater?
	if c.config.ExecCommand != "" {
		log.WithFields(log.Fields{
			"command": c.config.ExecCommand,
			"timeout": c.config.Timeout.String(),
		}).Info("calling external command")

		items := strings.Split(c.config.ExecCommand, " ")
		args := []string{c.config.CertificateFile(), c.config.PrivateKeyFile(), c.config.CAFile()}
		if len(items) > 1 {
			args = items[1:]
		}

		cmd := exec.Command(items[0], args...)
		cmd.Start()
		timer := time.AfterFunc(c.config.Timeout, func() {
			if err = cmd.Process.Kill(); err != nil {
				log.Error("external command took too long, operation timed out")
			}
		})
		err = cmd.Wait()
		timer.Stop()
		if err != nil {
			log.WithFields(log.Fields{
				"command": c.config.ExecCommand,
				"error":   err.Error(),
			}).Error("error calling external command")
		}
	}

	return nil
}

// makeSigningRequest is responsible for making the signing request
func (c *controller) doSigningRequest(request *SigningRequest) (*SigningResponse, error) {
	// @check if this a authenticated request
	auth := c.config.EndpointToken != ""

	var url string
	var body interface{}
	switch auth {
	case false:
		url = fmt.Sprintf("%s/api/v1/cfssl/sign", c.config.EndpointURL)
		body = request
	default:
		url = fmt.Sprintf("%s/api/v1/cfssl/authsign", c.config.EndpointURL)
		body = &AuthSigningRequest{Token: c.config.EndpointToken, Request: request}
	}

	// @step: marshal the json pay load
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	// @step: construct the http request
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(encoded))
	if err != nil {
		return nil, err
	}

	// @step: perform the actual request and decode the response
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	response := &SigningResponse{}
	if err := json.Unmarshal(content, response); err != nil {
		return nil, err
	}

	return response, nil
}
