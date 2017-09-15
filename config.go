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
	"errors"
	"fmt"
	"net/url"
)

// IsValid check if the config is valid
func (c *Config) IsValid() error {
	if _, err := url.Parse(c.EndpointURL); err != nil {
		return fmt.Errorf("invalid url: %s", err)
	}

	if len(c.Domains) <= 0 {
		return errors.New("no domains specified")
	}

	return nil
}

// PrivateKeyFile returns the path of the private key
func (c *Config) PrivateKeyFile() string {
	return fmt.Sprintf("%s/tls-key.pem", c.CertsDir)
}

// CertificateFile returns the path of the certificate file
func (c *Config) CertificateFile() string {
	return fmt.Sprintf("%s/tls.pem", c.CertsDir)
}
