package pkcs7

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"testing"
)

//
// Test key and certificate are in testdata/ and were generated with OpenSSL as follows:
//
//   openssl genrsa -out test.key 2048
//   openssl req -nodes -new -key test.key -out test.csr -subj "/C=CA/ST=Ontario/L=Toronto/O=Stefan Arentz/OU=Golang Hacks/CN=example.com"
//   openssl x509 -req -days 1825 -in test.csr -signkey test.key -out test.crt
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

func Test_Sign(t *testing.T) {
	key, err := loadPKCS1PrivateKey("testdata/test.key")
	if err != nil {
		panic(err)
	}

	cert, err := loadCertificate("testdata/test.crt")
	if err != nil {
		panic(err)
	}

	f, err := os.Open("testdata/test.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	signature, err := Sign(f, cert, key)
	if err != nil {
		t.Error("Cannot Sign:", err)
	}

	if len(signature) == 0 {
		t.Error("Signature is zero length")
	}
}
