// Positive fixture: SNOOT001, SNOOT013.
package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	_, _ = rsa.GenerateKey(rand.Reader, 2048) // SNOOT001
	_ = md5.New()                             // SNOOT013
}
