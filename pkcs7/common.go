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
	oidSha1                   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSha256                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRsaEncryption          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue `asn1:"explicit"`
	SerialNumber *big.Int
}

type SignerInfo struct {
	Version                   int
	SignedIdentifier          IssuerAndSerialNumber
	DigestAlgorithm           AlgorithmIdentifier
	AuthenticatedAttributes   Attributes `asn1:"tag:0"`
	DigestEncryptionAlgorithm AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes int `asn1:"optional"`
}

type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional"`
}

type SignedData struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	ContentInfo      ContentInfo
	Certificates     asn1.RawValue `asn1:"optional"`
	Crls             asn1.RawValue `asn1:"optional"`
	SignerInfos      []SignerInfo  `asn1:"set"`
}

type SignedDataWrapper struct {
	Oid        asn1.ObjectIdentifier
	SignedData asn1.RawValue
}

//

type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []interface{} `asn1:"set"`
}

type Attributes []Attribute

func NewAttribute(typ asn1.ObjectIdentifier, val interface{}) Attribute {
	if t, ok := val.(time.Time); ok {
		val = asn1.RawValue{Tag: 23, Bytes: []byte(t.Format("060102150405Z"))}
	}
	return Attribute{Type: typ, Values: []interface{}{val}}
}
