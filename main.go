package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// generating RSA public and private key pair
func generateRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error occured while generating key pair ")
		return nil, nil
	}
	return privateKey, &privateKey.PublicKey
}

// sign With Private key
func signWithPrivateKey(message string, privatekey *rsa.PrivateKey) string {

	byteMessage := []byte(message)
	hashed := sha256.New()
	hashed.Write(byteMessage)
	digest := hashed.Sum(nil)

	signed, err := rsa.SignPKCS1v15(rand.Reader, privatekey, crypto.SHA256, digest)
	if err != nil {
		fmt.Println("Error Occured While Signing With Private Key")
		return ""
	}

	signedstring := string(signed)
	return signedstring
}

// verify The Signature
func verifySignature(message string, signed string, publickey *rsa.PublicKey) {

	byteMessage := []byte(message)
	byteSigned := []byte(signed)
	hashed := sha256.New()
	hashed.Write(byteMessage)
	digest := hashed.Sum(nil)

	err := rsa.VerifyPKCS1v15(publickey, crypto.SHA256, digest, byteSigned)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("\n\n ==================== \n\n")
	fmt.Println("VERIFIED")
	return

}

// main function
func main() {
	//Invoking Generate Key Pair Function
	privateKey, publicKey := generateRSAKeyPair()

	//Invoking Sign With Private Key Function
	signed := signWithPrivateKey("hello anuradh", privateKey)

	//Invoking Verify Signature Function
	verifySignature("hello anuradh", signed, publicKey)
}
