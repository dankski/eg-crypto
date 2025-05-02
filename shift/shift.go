package shift

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
