package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// generate Private Key From Base64
// assume that your/server public key is shared with other party and server private key/base64 of the key is in a secure place
// using that base64 we generate a private key
func generatePrivateKeyFromBase64(privatekeystring string) *rsa.PrivateKey {

	base64Data := []byte(privatekeystring)
	d := make([]byte, base64.StdEncoding.DecodedLen(len(base64Data)))
	n, err := base64.StdEncoding.Decode(d, base64Data)
	if err != nil {
		fmt.Println("Error Occured while decoding  @ line 44 :", err)
		return nil
	}

	d = d[:n]
	key, err := x509.ParsePKCS1PrivateKey(d)
	if err != nil {
		fmt.Println("Error Occured while generating private key @ line 50 :", err)
		return nil
	}

	return key
}

// decrypt with Private key Which is encrpted by Publick Key.
// assume that your/server public key is shared with third party in key handshake .
// and message is encrypted with your/server public key.
// you will get only the encrypted message in base64 format
// you have to deoce the string first and then decrypt it from your/server private key
// This is tested with iOS and encrypted message was "Testing Method"
func decryptWithPrivateKey(encryptedmessage string, privatekey *rsa.PrivateKey) string {

	// need to decode base64 string which is encoded
	decodedByte, _ := base64.StdEncoding.DecodeString(encryptedmessage)
	decodeString := string(decodedByte)
	fmt.Println("Decoded String : ", decodeString)

	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privatekey, decodedByte)
	if err != nil {
		fmt.Println("Error occured while decryption")
		return ""
	}

	decryptedString := string(plainText)
	return decryptedString
}

// main function
func main() {
	fmt.Println("Working fine")
	privatekey := generatePrivateKeyFromBase64("MIIBOgIBAAJBAKYr9bOfsOHkP3/KZAb1O8UGa6xhV4FhbIHNyne385HC2Dh3/3C5xzJpT9MU9ksnrsjEacfCXLZonstOwe3KGosCAwEAAQJAKKzWBdPvDjw6tuMpvPJGYSIDNTzWmJrqXpOrHcbvXhw4qz4MrKe9veoEteOFwJuczROAJo43vYGjlx84odwlQQIhAM+o5LhurN4/b00gk+Hu1pf21n4bQC32Z1BWef+I3XBRAiEAzNqppueuVfr9zHDx0DenuB0WVsB7cY4ZGTU9tCycohsCIQCHaNuURF8nIXhDc93asvJt74CYhM6J6iYeZfVxot66sQIgM2QTtWxfvvAlZXlcIIklyTl61i6ZiUZFo55IqX+bl8sCIBaOKVVAGNWg20iLHZQQc64Dg68caNlQnUBPmrV2QriS")
	decryptedText := decryptWithPrivateKey("QYv3yDExOpW9zZHLZFCqFsE8ikUBEJbeSRaTx4MW7BUgSYv9qy7FmZ2OPjB6Bw5nSheFOuwAwdUhDUEHzjML7w==", privatekey)
	fmt.Println("Decrypted Text : ", decryptedText)
}
