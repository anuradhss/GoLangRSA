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

// decrypt with private key
func decryptWithPrivateKey(encryptedmessage string, privatekey *rsa.PrivateKey) string {

	byteEncryptedMessage := []byte(encryptedmessage)
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privatekey, byteEncryptedMessage)
	if err != nil {
		fmt.Println("Error occured while decryption")
		return ""
	}

	decryptedString := string(plainText)
	return decryptedString
}

// main function
func main() {
	fmt.Println("App Starts ...")
	fmt.Printf("\n\n ========================== Generating RSA Key Pair ========================== \n\n")
	privatekey, publickey := generateRSAKeypair()
	fmt.Println("Private Key :", privatekey)
	fmt.Println("Publick Key : ", publickey)
	fmt.Printf("\n\n ========================== Enctrypt Given Message With Public Key ========================== \n\n")
	encryptedMessage := encryptWithPublicKey("hello anuradh", publickey)
	fmt.Println("Encrypted Message  :", encryptedMessage)
	fmt.Printf("\n\n ========================== Decrypt Given Encrypted Message With Private Key ========================== \n\n")
	decryptedMessage := decryptWithPrivateKey(encryptedMessage, privatekey)
	fmt.Println("Decrypted Message : ", decryptedMessage)
}
