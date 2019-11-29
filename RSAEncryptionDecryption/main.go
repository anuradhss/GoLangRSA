package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// generate RSA KeyPair -> Public Key and Private Key
func generateRSAKeypair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil
	}
	return privateKey, &privateKey.PublicKey
}

// encrypt with publick key
func encryptWithPublicKey(message string, publickey *rsa.PublicKey) string {

	byteMessage := []byte(message)
	//hash := sha256.New()
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publickey, byteMessage)
	if err != nil {
		fmt.Println("Error occured while encryption")
		return ""
	}

	encryptedString := string(cipherText)
	return encryptedString
}

// main function
func main() {
	fmt.Println("working fine")
}
