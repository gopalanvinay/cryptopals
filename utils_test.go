package cryptopals

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestConvertHexToBase64(t *testing.T) {
	testcases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "basic",
			input: "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
			want:  "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
		},
		{
			name:  "for-xor",
			input: "1c0111001f010100061a024b53535009181c",
			want:  "HAERAB8BAQAGGgJLU1NQCRgc",
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			s, err := convertHexToBase64(tt.input)
			if err != nil {
				t.Fatalf("did not expect error")
			}
			if s != tt.want {
				t.Errorf("got %s, want %s", s, tt.want)
			}
		})
	}
}

func TestXOR(t *testing.T) {
	testcases := []struct {
		name           string
		hexA           string
		hexB           string
		expectedOutput string
	}{
		{
			name:           "basic",
			hexA:           "1c0111001f010100061a024b53535009181c",
			hexB:           "686974207468652062756c6c277320657965",
			expectedOutput: "746865206b696420646f6e277420706c6179",
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			a, err := hex.DecodeString(tt.hexA)
			if err != nil {
				t.Fatalf("did not expect error")
			}

			b, err := hex.DecodeString(tt.hexB)
			if err != nil {
				t.Fatalf("did not expect error")
			}

			out, err := xor([]byte(a), []byte(b))
			if err != nil {
				t.Errorf("received unexpected error %s", err.Error())
			}
			if hex.EncodeToString(out) != tt.expectedOutput {
				t.Errorf("got %s, want %s", string(out), tt.expectedOutput)
			}
		})
	}
}

func TestHamming(t *testing.T) {
	testcases := []struct {
		name string
		a    string
		b    string
		want int
	}{
		{
			name: "basic",
			a:    "this is a test",
			b:    "wokka wokka!!!",
			want: 37,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			a := []byte(tt.a)
			b := []byte(tt.b)

			h, err := hamming(a, b)
			if err != nil {
				t.Fatalf("did not expect error")
			}

			if h != tt.want {
				t.Errorf("got %d, want %d", h, tt.want)
			}
		})
	}
}

func TestAddPKCSPadding(t *testing.T) {
	testcases := []struct {
		name           string
		input          []byte
		expectedLength int
		want           []byte
	}{
		{
			name:           "basic",
			input:          []byte("YELLOW SUBMARINE"),
			expectedLength: 20,
			want:           []byte("YELLOW SUBMARINE\x04\x04\x04\x04"),
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {

			out := addPKCSPadding(tt.input, tt.expectedLength)

			if len(out) != tt.expectedLength {
				t.Errorf("expected output to be of length %d; got %d\n", tt.expectedLength, len(out))
			}

			if bytes.Compare(out, tt.want) != 0 {
				t.Errorf("got %+v, want %+v\n", tt.want, out)
			}
		})
	}
}

func TestRemovePKCSPadding(t *testing.T) {
	testcases := []struct {
		name  string
		input []byte
		want  []byte
	}{
		{
			name:  "basic",
			input: []byte("YELLOW SUBMARINE\x04\x04\x04\x04"),
			want:  []byte("YELLOW SUBMARINE"),
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {

			out := removePKCSPadding(tt.input)

			if len(out) != len(tt.want) {
				t.Errorf("expected output to be of length %d; got %d\n", len(tt.want), len(out))
			}

			if bytes.Compare(out, tt.want) != 0 {
				t.Errorf("got %+v, want %+v\n", tt.want, out)
			}
		})
	}
}

func TestRandStringRunes(t *testing.T) {
	testcases := []struct {
		name   string
		length int
	}{
		{
			name:   "128",
			length: 128,
		},
		{
			name:   "256",
			length: 256,
		},
		{
			name:   "23",
			length: 23,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {

			out := randStringRunes(tt.length)

			if len(out) != tt.length {
				t.Errorf("expected output to be of length %d; got %d\n", tt.length, len(out))
			}
		})
	}
}
