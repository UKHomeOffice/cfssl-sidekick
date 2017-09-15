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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

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
	_, csr, err := createCertificateRequest(c.config)
	if err != nil {
		return fmt.Errorf("failed to generate csr: %s", err)
	}

	// @step: encode the CSR into the pem block
	encoded, err := encodeCertificateRequest(csr)
	if err != nil {
		return fmt.Errorf("failed to encode csr: %s", err)
	}

	// @step: create an operational timeout
	doneCh := makeOperationTimeout(c.config.Timeout)

	for {
		log.WithFields(log.Fields{
			"domains":  strings.Join(c.config.Domains, ","),
			"endpoint": c.config.EndpointURL,
			"profile":  c.config.EndpointProfile,
		}).Info("attempting to acquire certificate from ca")

		// @step: requesting a signing of the certificate
		response, err := c.doSigningRequest(&SigningRequest{
			CertificateRequest: encoded,
			Profile:            c.config.EndpointProfile,
			Bundle:             true,
		})

		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Error("failed to retrieve certificate signing")

			time.Sleep(5 * time.Second)
			continue
		}

		if err := c.handleCertificateResponse(response); err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Error("failed to proccess certificate response")

			time.Sleep(5 * time.Second)
			continue
		}

		log.WithFields(log.Fields{
			"certificate": c.config.CertificateFile(),
			"private_key": c.config.PrivateKeyFile(),
		}).Info("successfully wrote the tls certificates")

		// indicate a success and stop the operational timeout
		doneCh <- true

		// @step: write the private key and certificate to disk

		if c.config.Onetime {
			log.Info("onetime mode enabled, exiting the service")
			os.Exit(0)
		}

		time.Sleep(10 * time.Minute)
	}
}

// handleCertificateResponse is responsible for handling the certificate response
func (c *controller) handleCertificateResponse(response *SigningResponse) error {
	// @check the response was successful
	if !response.Success {
		return fmt.Errorf("unsuccessful operation, errors: %s", response.Errors[0].Message)
	}

	// @check we have a certificate
	if response.Result["certificate"] == "" {
		return errors.New("no certificate found in the response")
	}

	log.WithFields(log.Fields{
		"path": c.config.CertificateFile(),
	}).Info("writing the certificate to disk")

	content := response.Result["certificate"]
	file, err := os.OpenFile(c.config.CertificateFile(), os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.FileMode(0600))
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		return err
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
