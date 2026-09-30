package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func makeKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
