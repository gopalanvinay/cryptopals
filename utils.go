package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func init() {
	rand.Seed(time.Now().UnixNano())
}

func convertHexToBase64(s string) (string, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

func xor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("expected equal length buffers; a=%d, b=%d", len(a), len(b))
	}

	c := make([]byte, len(a))
	for i := range a {
		c[i] = a[i] ^ b[i]
	}

	return c, nil
}

func hamming(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, fmt.Errorf("require arrays to be of equal length; a= %d, b=%d", len(a), len(b))
	}

	var diff int

	msg, err := xor(a, b)
	if err != nil {
		return 0, err
	}
	for i := range a {
		var mask byte
		for j := 0; j < 8; j++ {
			mask = (1 << j)
			if (mask & msg[i]) == mask {
				diff += 1
			}
		}
	}

	return diff, nil
}

func addPKCSPadding(data []byte, outputLength int) []byte {
	currentLength := len(data)
	output := data
	extraBytes := outputLength - currentLength
	for i := 0; i < extraBytes; i++ {
		output = append(output, byte(extraBytes))
	}

	return output
}

func removePKCSPadding(data []byte) []byte {
	currentLength := len(data)
	bytesToRemove := int(data[currentLength-1])
	output := data[0:(currentLength - bytesToRemove)]

	return output
}

// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go
func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
