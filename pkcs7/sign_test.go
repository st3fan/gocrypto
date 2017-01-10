package pkcs7

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
)

//
// Test key and certificate are in testdata/ and were generated with OpenSSL as follows:
//
//   openssl genrsa -out test1.key 2048
//   openssl req -nodes -new -key test1.key -out test1.csr -subj "/C=CA/ST=Ontario/L=Toronto/O=Stefan Arentz/OU=Golang Hacks/CN=example.com"
//   openssl x509 -req -days 1825 -in test1.csr -signkey test1.key -out test1.crt
//

func loadPKCS1PrivateKey(path string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("Invalid key; no PEM data found")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("Invalid key; no RSA PRIVATE KEY block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func loadCertificate(path string) (*x509.Certificate, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("Invalid certificate; no PEM data found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, errors.New("Invalid certificate; no CERTIFICATE block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func verifySignature(file string, signature []byte) error {
	if err := ioutil.WriteFile("/tmp/signature", signature, 0600); err != nil {
		return err
	}

	cmd := exec.Command("openssl", "smime", "-verify", "-in", "/tmp/signature", "-content", file, "-inform", "der", "-noverify")
	if err := cmd.Start(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	return nil
}

func Test_Sign(t *testing.T) {
	cases := []struct {
		FileName    string
		Certificate string
		PrivateKey  string
		Error       string
	}{
		{
			FileName:    "testdata/test1.txt",
			Certificate: "testdata/test1.crt",
			PrivateKey:  "testdata/test1.key",
			Error:       "",
		},
	}

	for _, c := range cases {
		cert, err := loadCertificate(c.Certificate)
		if err != nil {
			t.Errorf("%v", err.Error())
			continue
		}

		key, err := loadPKCS1PrivateKey(c.PrivateKey)
		if err != nil {
			t.Errorf("%v", err.Error())
			continue
		}

		f, err := os.Open(c.FileName)
		if err != nil {
			t.Errorf("%v", err.Error())
			continue
		}
		defer f.Close()

		signature, err := Sign(f, cert, key)

		if c.Error != "" {
			// Sign should fail
			if err != nil && err.Error() == c.Error {
				continue
			}

			t.Errorf("Expected Error %v, found %v", c.Error, err)
			continue
		}

		if len(signature) <= 0 {
			t.Errorf("Signature is zero length")
			continue
		}

		if err := verifySignature(c.FileName, signature); err != nil {
			t.Errorf("Failed to verify signature with openssl: %v", err.Error())
		}
	}
}
