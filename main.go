package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// declaring public and private key to hold keys
var _publicKey rsa.PublicKey
var _privateKey rsa.PrivateKey

// generate RSA key pair -> public key and private key
func generateKeyPair() {
	reader := rand.Reader
	bitSize := 512

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		fmt.Println("Error Encountered : ", err)
	}

	_publicKey := key.PublicKey
	_privateKey := key

	fmt.Println("public key : ", _publicKey)
	fmt.Println("private key : ", _privateKey)
}

// main function
func main() {
	fmt.Println("working fine")
	generateKeyPair()
}
