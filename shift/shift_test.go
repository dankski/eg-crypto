package shift_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/dankski/shift"
)

var testKey = bytes.Repeat([]byte{1}, shift.BlockSize)

var cipherCases = []struct {
	plaintext, ciphertext []byte
}{
	{
		plaintext:  []byte{0, 1, 2, 3, 4, 5},
		ciphertext: []byte{1, 2, 3, 4, 5, 6},
	},
}

func TestEncrypt(t *testing.T) {
	t.Parallel()

	block, err := shift.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range cipherCases {
		name := fmt.Sprintf("%x + %x = %x", tc.plaintext, testKey, tc.ciphertext)
		t.Run(name, func(t *testing.T) {
			got := make([]byte, len(tc.plaintext))
			block.Encrypt(got, tc.plaintext)
			if !bytes.Equal(tc.ciphertext, got) {
				t.Errorf("want %x, got %x", tc.ciphertext, got)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	t.Parallel()

	block, err := shift.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range cipherCases {
		name := fmt.Sprintf("%x - %x = %x", tc.ciphertext, testKey, tc.plaintext)

		t.Run(name, func(t *testing.T) {
			got := make([]byte, len(tc.ciphertext))
			block.Decrypt(got, tc.ciphertext)
			if !bytes.Equal(tc.plaintext, got) {
				t.Errorf("want %x, got %x", tc.plaintext, got)
			}
		})
	}
}

func TestNewCipherGivesNoErrorForValidKey(t *testing.T) {
	t.Parallel()
	_, err := shift.NewCipher(make([]byte, shift.BlockSize))
	if err != nil {
		t.Fatalf("want no error, got: %v", err)
	}
}

func TestNewCipherGivesErrorForInvalidKey(t *testing.T) {
	t.Parallel()
	_, err := shift.NewCipher([]byte{})
	if !errors.Is(err, shift.ErrKeySize) {
		t.Errorf("want ErrKeySize, got %v", err)
	}
}

func TestBlockSizeReturnsBlockSize(t *testing.T) {
	t.Parallel()
	block, err := shift.NewCipher(make([]byte, shift.BlockSize))

	if err != nil {
		t.Fatal(err)
	}

	want := shift.BlockSize
	got := block.BlockSize()

	if want != got {
		t.Errorf("want %d, got %d", want, got)
	}
}

func TestEncrypterEnciphersBlockAlignedMessage(t *testing.T) {
	t.Parallel()

	plaintext := []byte("This message is exactly 32 bytes")

	block, err := shift.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}

	enc := shift.NewEncrypter(block)
	want := []byte("Uijt!nfttbhf!jt!fybdumz!43!czuft")
	got := make([]byte, 32)
	enc.CryptBlocks(got, plaintext)

	if !bytes.Equal(want, got) {
		t.Errorf("want %x, got %x", want, got)
	}
}
