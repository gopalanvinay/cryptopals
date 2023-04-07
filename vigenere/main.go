package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	crypto "github.com/gopalavinay/cryptopals"
)

func main() {
	fileName := os.Args[1]
	fileContent, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
	}

	// Convert []byte to string
	ciphertext := string(fileContent)
	plainText, key, err := crypto.DecodeVigenere(ciphertext)
	if err != nil {
		log.Fatalf("error decoding keysize: %s", err)
	}

	fmt.Printf("Plaintext: %s\n", plainText)
	fmt.Printf("Data encrypted with key: %s\n", key)

}
