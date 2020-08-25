package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)
type Certificate struct {
	// Cerificate in ASN.1 DER format
	Certificate []byte
	// Private key in ASN.1 DER format
	PrivateKey []byte
}
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

type pkcs1AdditionalRSAPrime struct {
	Prime *big.Int

	// We ignore these values because rsa will calculate them.
	Exp   *big.Int
	Coeff *big.Int
}

type pkcs1PrivateKey struct {
	Version int
	N       *big.Int
	E       int
	D       *big.Int
	P       *big.Int
	Q       *big.Int
	// We ignore these values, if present, because rsa will calculate them.
	Dp   *big.Int `asn1:"optional"`
	Dq   *big.Int `asn1:"optional"`
	Qinv *big.Int `asn1:"optional"`

	AdditionalPrimes []pkcs1AdditionalRSAPrime `asn1:"optional,omitempty"`
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func Generate(parent *Certificate) (*Certificate, error) {
	var (
		pKey      interface{}
		parentKey interface{}
		err       error
	)
	// higher signing performance than RSA2048
	selfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil
	}
	parentKey = selfKey
	if parent != nil {
		if _, e := asn1.Unmarshal(parent.PrivateKey, &ecPrivateKey{}); e == nil {
			pKey, err = x509.ParseECPrivateKey(parent.PrivateKey)
		} else if _, e := asn1.Unmarshal(parent.PrivateKey, &pkcs8{}); e == nil {
			pKey, err = x509.ParsePKCS8PrivateKey(parent.PrivateKey)
		} else if _, e := asn1.Unmarshal(parent.PrivateKey, &pkcs1PrivateKey{}); e == nil {
			pKey, err = x509.ParsePKCS1PrivateKey(parent.PrivateKey)
		}
		if err != nil {
			panic(err)
		}
		parentKey = pKey
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             time.Now().Add(time.Hour * -1),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}


	parentCert := template
	if parent != nil {
		pCert, err := x509.ParseCertificate(parent.Certificate)
		if err != nil {
			panic(err)
		}
		parentCert = pCert
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, publicKey(selfKey), parentKey)
	if err != nil {
		panic(err)
	}

	privateKey, err := x509.MarshalPKCS8PrivateKey(selfKey)
	if err != nil {
		panic(err)
	}

	return &Certificate{
		Certificate: derBytes,
		PrivateKey:  privateKey,
	}, nil
}

