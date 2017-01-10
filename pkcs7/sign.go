// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package pkcs7

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"time"
)

// Create a signature from io.Reader
// Returns the signature and any error encountered.
func Sign(reader io.Reader, certificate *x509.Certificate, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashable := NewHashableReader(reader)
	return SignDataIntermediate(hashable, certificate, privateKey, nil)
}

// Create a signature from io.Reader including intermediate certificates.
// Returns the signature and any error encountered.
func SignIntermediate(reader io.Reader, certificate *x509.Certificate, privateKey *rsa.PrivateKey, intermediateCertificates []*x509.Certificate) ([]byte, error) {
	hashable := NewHashableReader(reader)
	return SignDataIntermediate(hashable, certificate, privateKey, intermediateCertificates)
}

// Creates a signature
// Returns the signature and any error encountered.
func SignData(hashable Hashable, certificate *x509.Certificate, privateKey *rsa.PrivateKey) ([]byte, error) {
	return SignDataIntermediate(hashable, certificate, privateKey, nil)
}

// Create a signature including intermediate certificates.
// Returns the signature and any error encountered.
func SignDataIntermediate(hashable Hashable, certificate *x509.Certificate, privateKey *rsa.PrivateKey, intermediateCertificates []*x509.Certificate) ([]byte, error) {
	// Check if parameters are valid
	if certificate == nil {
		return nil, errors.New("\"certificate\" cannot be nil.")
	}

	if privateKey == nil {
		return nil, errors.New("\"privateKey\" cannot be nil.")
	}

	messageDigest, err := hashable.Sha256()
	if err != nil {
		return nil, err
	}

	// Copy intermediateCertificates to certificate stack
	raw := certificate.Raw
	for _, intermediate := range intermediateCertificates {
		if intermediate != nil {
			raw = append(raw, intermediate.Raw...)
		}
	}

	signedData := signedData{
		Version: 1,
		DigestAlgorithms: []algorithmIdentifier{
			{
				Algorithm: oidSHA256,
				Parameters: asn1.RawValue{
					Tag: 5,
				},
			},
		},
		ContentInfo: contentInfo{
			ContentType: oidPKCS7Data,
		},
		Certificates: asn1.RawValue{
			Class:      2,
			Tag:        0,
			Bytes:      raw,
			IsCompound: true,
		},
		SignerInfos: []signerInfo{
			{
				Version: 1,
				SignedIdentifier: issuerAndSerialNumber{
					Issuer: asn1.RawValue{
						FullBytes: certificate.RawIssuer,
					},
					SerialNumber: certificate.SerialNumber,
				},
				DigestAlgorithm: algorithmIdentifier{
					Algorithm: oidSHA256,
					Parameters: asn1.RawValue{
						Tag: 5,
					},
				},
				AuthenticatedAttributes: []attribute{
					newAttribute(oidPKCS9ContentType, oidPKCS7Data),
					newAttribute(oidPKCS9SigningTime, time.Now().UTC()),
					newAttribute(oidPKCS9MessageDigest, messageDigest),
				},
				DigestEncryptionAlgorithm: algorithmIdentifier{
					Algorithm: oidPKCS1RSAEncryption,
					Parameters: asn1.RawValue{
						Tag: 5,
					},
				},
				EncryptedDigest:           nil, // We fill this in later
				UnauthenticatedAttributes: 0,
			},
		},
	}

	encodedAuthenticatedAttributes, err := asn1.Marshal(signedData.SignerInfos[0].AuthenticatedAttributes)
	if err != nil {
		return nil, err
	}

	originalFirstByte := encodedAuthenticatedAttributes[0]
	encodedAuthenticatedAttributes[0] = 0x31

	digest := NewHashableBytes(encodedAuthenticatedAttributes)
	attributesDigest, err := digest.Sha256()
	if err != nil {
		return nil, err
	}

	encodedAuthenticatedAttributes[0] = originalFirstByte

	encryptedDigest, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, attributesDigest)
	if err != nil {
		return nil, err
	}
	signedData.SignerInfos[0].EncryptedDigest = encryptedDigest

	encodedSignedData, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, err
	}

	signedDataWrapper := signedDataWrapper{
		Oid:        oidPKCS7SignedData,
		SignedData: asn1.RawValue{Class: 2, Tag: 0, Bytes: encodedSignedData, IsCompound: true},
	}

	return asn1.Marshal(signedDataWrapper)
}
