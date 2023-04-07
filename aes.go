package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func EncryptAES_CBC(plaintext, key []byte) ([]byte, bool, error) {
	blockSize := 16
	preparedPlaintextData := prepareAESBlocks(plaintext, blockSize)
	dataLength := len(preparedPlaintextData)

	paddingAdded := len(plaintext)%blockSize != 0

	iv := setupRandomIV(blockSize)
	// account for iv which will be added
	encryptedData := make([][]byte, dataLength)

	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	for i := 0; i < dataLength; i++ {
		var pi []byte
		var err error
		if i == 0 {
			pi, err = xor(preparedPlaintextData[i], iv)
			if err != nil {
				return nil, false, err
			}
		} else {
			pi, err = xor(preparedPlaintextData[i], encryptedData[i-1])
			if err != nil {
				return nil, false, err
			}
		}

		ci := encryptSingleAESBlock(c, pi, blockSize)
		encryptedData[i] = ci
	}

	// add iv to the beginning of encrypted message
	ret := append([][]byte{iv}, encryptedData...)

	return bytes.Join(ret, nil), paddingAdded, nil
}

func DecryptAES_CBC(cipher, key []byte, removePadding bool) ([]byte, error) {
	blockSize := 16
	preparedCipherData := prepareAESBlocks(cipher, blockSize)
	dataLength := len(preparedCipherData)

	// iv is first block of cipher data
	iv := preparedCipherData[0]
	decryptedData := make([][]byte, dataLength)

	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	for i := 0; i < dataLength; i++ {
		d := decryptSingleAESBlock(c, preparedCipherData[i], blockSize)
		var pi []byte
		var err error
		if i == 0 {
			pi, err = xor(d, iv)
			if err != nil {
				return nil, err
			}
		} else {
			pi, err = xor(d, decryptedData[i-1])
			if err != nil {
				return nil, err
			}
		}

		decryptedData[i] = pi
	}

	decrypted := bytes.Join(decryptedData, nil)

	// if removePadding {
	// 	decrypted = removePKCSPadding(decrypted)
	// }

	return decrypted, nil
}

func EncryptAES_ECB(plaintext, key []byte) ([]byte, bool) {
	// size in bytes
	blockSize := 16
	preparedPlaintextData := prepareAESBlocks(plaintext, blockSize)
	dataLength := len(preparedPlaintextData)

	paddingAdded := len(plaintext)%blockSize != 0

	encryptedBlocks := make([][]byte, dataLength)

	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	for i, cipherBlock := range preparedPlaintextData {
		encrypted := make([]byte, 16)
		c.Encrypt(encrypted, cipherBlock)

		encryptedBlocks[i] = encrypted
	}

	return bytes.Join(encryptedBlocks, nil), paddingAdded
}

func DecryptAES_ECB(cipher, key []byte, removePadding bool) []byte {
	// size in bytes
	blockSize := 16
	// preparedCipherData := prepareAESBlocks(cipher, blockSize)
	preparedCipherData := sliceBlocksByKeyLength(cipher, blockSize)
	dataLength := len(preparedCipherData)

	decryptedBlocks := make([][]byte, dataLength)
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	for i, cipherBlock := range preparedCipherData {
		decrypted := make([]byte, 16)
		c.Decrypt(decrypted, cipherBlock)

		decryptedBlocks[i] = decrypted
	}

	decrypted := bytes.Join(decryptedBlocks, nil)

	if removePadding {
		decrypted = removePKCSPadding(decrypted)
	}

	return decrypted
}

// detects if data has undergone AES Encryption
func DetectAESECB(cipher []byte) (bool, int, error) {
	blockSize := 16
	cipherBlocks := sliceBlocksByKeyLength(cipher, blockSize)

	zeroHammingCounter := 0

	for i := 0; i < len(cipherBlocks)-1; i++ {
		for j := i + 1; j < len(cipherBlocks); j++ {
			dist, err := hamming(cipherBlocks[i], cipherBlocks[j])
			if err != nil {
				return false, 0, err
			}

			if dist == 0 {
				zeroHammingCounter++
			}
		}
	}

	return zeroHammingCounter > 0, zeroHammingCounter, nil

}

func encryptSingleAESBlock(c cipher.Block, block []byte, blockSize int) []byte {
	encrypted := make([]byte, blockSize)
	c.Encrypt(encrypted, block)

	return encrypted
}

func decryptSingleAESBlock(c cipher.Block, block []byte, blockSize int) []byte {
	decrypted := make([]byte, blockSize)
	c.Decrypt(decrypted, block)

	return decrypted
}

func prepareAESBlocks(input []byte, blockSize int) [][]byte {
	currentLength := len(input)
	data := input
	extraBytes := currentLength % blockSize
	if extraBytes != 0 {
		currentLength = currentLength + (blockSize - extraBytes)
		data = addPKCSPadding(data, currentLength)
	}

	numBlocks := currentLength / blockSize
	aesBlocks := make([][]byte, numBlocks)

	for i := 0; i < numBlocks; i++ {
		block := data[i*blockSize : (i*blockSize + blockSize)]
		aesBlocks[i] = block
	}

	return aesBlocks
}

func setupRandomIV(blockSize int) []byte {
	return []byte(randStringRunes(blockSize))
}
