package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// generate Publick Key From base64 string
func generatePublickKeyFromBase64(publickeystring string) *rsa.PublicKey {

	base64Data := []byte(publickeystring)
	d := make([]byte, base64.StdEncoding.DecodedLen(len(base64Data)))
	n, err := base64.StdEncoding.Decode(d, base64Data)
	if err != nil {
		fmt.Println("Error Occured while decoding @ line 17 :", err)
		return nil
	}

	d = d[:n]
	key, err := x509.ParsePKCS1PublicKey(d)
	if err != nil {
		fmt.Println("Error Occured while generating publick key @ line 24 :", err)
		return nil
	}
	return key
}

// get base64 string from public key to test keys are two identical
func generateBase64FromPublickKey(publickey *rsa.PublicKey) {

	publicKeyByte := x509.MarshalPKCS1PublicKey(publickey)
	publicKeyString := base64.StdEncoding.EncodeToString(publicKeyByte)
	fmt.Println(publicKeyString)
}

// generate Private Key from base64
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

// get base64 string from private key to test keys are two identical
func generateBase64FromPrivateKey(privatekey *rsa.PrivateKey) {

	privateKeyByte := x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyString := base64.StdEncoding.EncodeToString(privateKeyByte)
	fmt.Println(privateKeyString)
}

// sign with generated private key
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

// verify the signature with publick key
func verifySignatureWithPublicKey(message string, signed string, publickey *rsa.PublicKey) {

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
	fmt.Println("VERIFIED")
	return
}

func main() {
	fmt.Println("Working Properly with signed : kLqqHbvfPn0HM3zDS5HWc8rK4DcpEAsGClRVjZP9e0KZzODo+8f38X1ZEMOZ+PjtSmA/H+g42q2VxEu1y+Pq3A== && text : Hello")
	fmt.Printf("\n\n ================ Generating Publick Key ================== \n\n")
	publicSecKey := generatePublickKeyFromBase64("MEgCQQCmK/Wzn7Dh5D9/ymQG9TvFBmusYVeBYWyBzcp3t/ORwtg4d/9wuccyaU/TFPZLJ67IxGnHwly2aJ7LTsHtyhqLAgMBAAE=")
	fmt.Println(publicSecKey)
	fmt.Printf("\n\n ================ Generating Publick Key Base64 ================== \n\n")
	generateBase64FromPublickKey(publicSecKey)
	fmt.Printf("\n\n ================ Generating Private Key ================== \n\n")
	privateSecKey := generatePrivateKeyFromBase64("MIIBOgIBAAJBAKYr9bOfsOHkP3/KZAb1O8UGa6xhV4FhbIHNyne385HC2Dh3/3C5xzJpT9MU9ksnrsjEacfCXLZonstOwe3KGosCAwEAAQJAKKzWBdPvDjw6tuMpvPJGYSIDNTzWmJrqXpOrHcbvXhw4qz4MrKe9veoEteOFwJuczROAJo43vYGjlx84odwlQQIhAM+o5LhurN4/b00gk+Hu1pf21n4bQC32Z1BWef+I3XBRAiEAzNqppueuVfr9zHDx0DenuB0WVsB7cY4ZGTU9tCycohsCIQCHaNuURF8nIXhDc93asvJt74CYhM6J6iYeZfVxot66sQIgM2QTtWxfvvAlZXlcIIklyTl61i6ZiUZFo55IqX+bl8sCIBaOKVVAGNWg20iLHZQQc64Dg68caNlQnUBPmrV2QriS")
	fmt.Println(privateSecKey)
	fmt.Printf("\n\n ================ Generating Private Key Base64 ================== \n\n")
	generateBase64FromPrivateKey(privateSecKey)
	fmt.Printf("\n\n ================ Sign With Generated Private Key ================== \n\n")
	signedPayLoad := signWithPrivateKey("Hello", privateSecKey)
	fmt.Println(signedPayLoad)
	fmt.Printf("\n\n ================ Verify With Generated Private Key ================== \n\n")
	verifySignatureWithPublicKey("Hello", signedPayLoad, publicSecKey)
}
