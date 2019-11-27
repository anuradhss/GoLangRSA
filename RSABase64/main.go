package main

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

func generatePublickKeyFromBase64(publickeystring string) {

	base64Data := []byte(publickeystring)
	d := make([]byte, base64.StdEncoding.DecodedLen(len(base64Data)))
	n, err := base64.StdEncoding.Decode(d, base64Data)
	if err != nil {
		fmt.Println("Error Occured @ line 15 :", err)
		return
	}

	d = d[:n]
	key, err := x509.ParsePKCS1PublicKey(d)
	if err != nil {
		fmt.Println("Error Occured @ line 22 :", err)
		return
	}

	fmt.Println(key)
}

func main() {
	fmt.Println("Working Properly")
	generatePublickKeyFromBase64("MEgCQQCdnQjRuoEXxfQhVIBHEpTzjDfj3Kz/7uaqpax2O73vcz4V0EoF1X/WJcl1Rh+qmxEoOHcGhq4sRwjMqDl6EPQtAgMBAAE=")
}
