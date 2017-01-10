// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package pkcs7

import (
	"encoding/asn1"
	"math/big"
	"time"
)

var (
	oidPKCS9ContentType       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidPKCS9MessageDigest     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidPKCS9SigningTime       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidCommonName             = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidOrganizationName       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnitName = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCountryName            = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidPKCS7Data              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKCS7SignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSHA1                   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidPKCS1RSAEncryption     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type signerInfo struct {
	Version                   int
	SignedIdentifier          issuerAndSerialNumber
	DigestAlgorithm           algorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"tag:0"`
	DigestEncryptionAlgorithm algorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes int `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	ContentInfo      contentInfo
	Certificates     asn1.RawValue `asn1:"optional"`
	Crls             asn1.RawValue `asn1:"optional"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type signedDataWrapper struct {
	Oid        asn1.ObjectIdentifier
	SignedData asn1.RawValue
}

//

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []interface{} `asn1:"set"`
}

func newAttribute(typ asn1.ObjectIdentifier, val interface{}) attribute {
	if t, ok := val.(time.Time); ok {
		val = asn1.RawValue{Tag: 23, Bytes: []byte(t.Format("060102150405Z"))}
	}
	return attribute{
		Type: typ,
		Values: []interface{}{
			val,
		},
	}
}
