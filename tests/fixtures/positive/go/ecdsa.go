package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func makeSigner() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
