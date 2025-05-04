package shift

import (
	"bytes"
	"errors"
)

func Encipher(plaintext []byte, key byte) (ciphertext []byte) {
	ciphertext = make([]byte, len(plaintext))
	for i, b := range plaintext {
		ciphertext[i] = b + key
	}
	return ciphertext
}

func Decipher(ciphertext []byte, key byte) (plaintext []byte) {
	plaintext = make([]byte, len(ciphertext))

	for i, b := range ciphertext {
		plaintext[i] = b - key
	}
	return plaintext
}


func Crack(ciphertext []byte, crib []byte) (key byte, err error) {
  for guess := range 256 {
    result := Decipher(ciphertext[:len(crib)], byte(guess))
    if bytes.Equal(result, crib) {
      return byte(guess), nil
    }
  }
  return 0, errors.New("no key found")
}
