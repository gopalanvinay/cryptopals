package cryptopals

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt_ECB(t *testing.T) {
	testcases := []struct {
		name      string
		plaintext []byte
		key       []byte
	}{
		{
			name:      "basic-1",
			plaintext: []byte("One of them has been encrypted with ECB"),
			key:       []byte("YELLOW SUBMARINE"),
		},
		{
			name:      "basic-2",
			plaintext: []byte("THIS IS A TEST STRING WITH NO TRAILING SPACES"),
			key:       []byte("YELLOW SUBMARINE"),
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {

			cipher, paddingAdded := EncryptAES_ECB(tt.plaintext, tt.key)
			decrypted := DecryptAES_ECB(cipher, tt.key, paddingAdded)

			if len(decrypted) != len(tt.plaintext) {
				t.Fatalf("expected decrypted text length to be equal to: %d; got %d", len(tt.plaintext), len(decrypted))

			}
			if bytes.Compare(decrypted, tt.plaintext) != 0 {
				t.Fatalf("expected decrypted text to be equal to text: %s; got %s", tt.plaintext, decrypted)
			}

		})
	}
}

func TestEncryptDecrypt_CBC(t *testing.T) {
	testcases := []struct {
		name      string
		plaintext []byte
		key       []byte
	}{
		{
			name:      "basic-1",
			plaintext: []byte("One of them has been encrypted with ECB"),
			key:       []byte("YELLOW SUBMARINE"),
		},
		{
			name:      "basic-2",
			plaintext: []byte("THIS IS A TEST STRING WITH NO TRAILING SPACES"),
			key:       []byte("YELLOW SUBMARINE"),
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {

			cipher, paddingAdded, err := EncryptAES_CBC(tt.plaintext, tt.key)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}
			decrypted, err := DecryptAES_CBC(cipher, tt.key, paddingAdded)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			if len(decrypted) != len(tt.plaintext) {
				t.Fatalf("expected decrypted text length to be equal to: %d; got %d", len(tt.plaintext), len(decrypted))

			}
			if bytes.Compare(decrypted, tt.plaintext) != 0 {
				t.Fatalf("expected decrypted text to be equal to text: %s; got %s", tt.plaintext, decrypted)
			}

		})
	}
}

func TestAESDetectECB(t *testing.T) {
	testcases := []struct {
		name      string
		plaintext []byte
		key       []byte
		isEncrypt bool
	}{
		{
			name:      "basic-1",
			plaintext: []byte("REPEATED STRING REPEATED STRING "),
			key:       []byte("YELLOW SUBMARINE"),
			isEncrypt: true,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {

			cipher := tt.plaintext
			if tt.isEncrypt {
				cipher, _ = EncryptAES_ECB(tt.plaintext, tt.key)

			}

			aesDetected, _, err := DetectAESECB(cipher)
			if err != nil {
				t.Fatal(err)

			}

			if aesDetected != tt.isEncrypt {
				t.Fatalf("expected isEncrypt output to be : %v", aesDetected)
			}

		})
	}
}

func TestPrepareAESBlocks(t *testing.T) {
	testcases := []struct {
		name      string
		input     []byte
		want      [][]byte
		blockSize int
		numBlocks int
	}{
		{
			name:      "basic",
			input:     []byte("THIS IS A TEST STRING"),
			want:      [][]byte{[]byte("THIS IS A TEST S"), []byte("TRING\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b")},
			blockSize: 16,
			numBlocks: 2,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {

			out := prepareAESBlocks(tt.input, tt.blockSize)

			if len(out) != tt.numBlocks {
				t.Errorf("expected output to be of length %d; got %d\n", tt.numBlocks, len(out))
			}

			for i, block := range out {
				if bytes.Compare(block, tt.want[i]) != 0 {
					t.Errorf("got two unequal aes blocks: %s != %s", block, tt.want[i])
				}
			}
		})
	}
}
