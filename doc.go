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

import "time"

var (
	// Version is the version on the sidekick
	Version = "v0.0.7"
	// GitSHA is the git sha we were built from
	GitSHA = "no set"
)

// AuthSigningRequest is a authenticated request
type AuthSigningRequest struct {
	Token   string          `json:"token"`
	Request *SigningRequest `json:"request"`
}

// SigningRequest is what is sent to cfssl
type SigningRequest struct {
	Bundle             bool     `json:"bundle"`
	CertificateRequest string   `json:"certificate_request"`
	CrlOverride        string   `json:"crl_override"`
	Hosts              []string `json:"hosts"`
	Label              string   `json:"label"`
	Profile            string   `json:"profile"`
}

// SigningResponse is what cfssl send back
type SigningResponse struct {
	Success bool `json:"success"`
	Result  struct {
		Bundle struct {
			Bundle      string      `json:"bundle"`
			CrlSupport  bool        `json:"crl_support"`
			Crt         string      `json:"crt"`
			Expires     time.Time   `json:"expires"`
			Hostnames   []string    `json:"hostnames"`
			Issuer      string      `json:"issuer"`
			Key         string      `json:"key"`
			KeySize     int         `json:"key_size"`
			KeyType     string      `json:"key_type"`
			LeafExpires time.Time   `json:"leaf_expires"`
			Ocsp        interface{} `json:"ocsp"`
			OcspSupport bool        `json:"ocsp_support"`
			Root        string      `json:"root"`
			Signature   string      `json:"signature"`
			Status      struct {
				Rebundled           bool          `json:"rebundled"`
				ExpiringSKIs        interface{}   `json:"expiring_SKIs"`
				UntrustedRootStores []interface{} `json:"untrusted_root_stores"`
				Messages            []string      `json:"messages"`
				Code                int           `json:"code"`
			} `json:"status"`
			Subject string `json:"subject"`
		} `json:"bundle"`
		Certificate string `json:"certificate"`
	} `json:"result"`
	Errors []SigningError `json:"errors"`
}

// SigningError is the cfssl error struct
type SigningError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Config is the configuration for the service
type Config struct {
	// EndpointURL is the cfssl endpoint
	EndpointURL string
	// EndpointToken is the cfssl token
	EndpointToken string
	// EndpointProfile is the profile to use
	EndpointProfile string
	// Domains is a list of domains to get
	Domains []string
	// Size is the size of the ceritificate
	Size int
	// Expiry the certificate rotation
	Expiry time.Duration
	// Organization
	Organization string
	// Country
	Country string
	// Locality
	Locality string
	// Province
	Province string
	// CertsDir is the directory to save the certificates
	CertsDir string
	// ExecCommand is a command to run
	ExecCommand string
	// Timeout is the timeout for an operation
	Timeout time.Duration
	// TLSCAPath is the path to a ca file
	TLSCAPath string
	// TLSCertificatename is the name of the certificate
	TLSCertificateFilename string
	// TLSPrivateKeyFilename is the name of the private key
	TLSPrivateKeyFilename string
	// TLSCAFilename is the name of the ca file
	TLSCAFilename string
	// Onetime indicated the service to run once
	Onetime bool
	// UpstreamURL is the upstream url
	UpstreamURL string
	// Verbose indicates verbose logging
	Verbose bool
}
