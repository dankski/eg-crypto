package shift

import (
	"crypto/cipher"
	"errors"
	"fmt"
)

const MaxKeyLen = 32
const BlockSize = 32

var ErrKeySize = errors.New("shift: invalid key size")

type shiftCipher struct {
	key [BlockSize]byte
}

func (c shiftCipher) Encrypt(dst, src []byte) {
	for i, b := range src {
		dst[i] = b + c.key[i]
	}
}

func (c shiftCipher) Decrypt(dst, src []byte) {
	for i, b := range src {
		dst[i] = b - c.key[i]
	}
}

func (c shiftCipher) BlockSize() int {
	return BlockSize
}

func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != BlockSize {
		return nil, fmt.Errorf("%w %d (must be %d)", ErrKeySize, len(key), BlockSize)
	}

	return &shiftCipher{
		key: [BlockSize]byte(key),
	}, nil
}

type encrypter struct {
	block     cipher.Block
	blockSize int
}

func NewEncrypter(block cipher.Block) cipher.BlockMode {
	return &encrypter{
		block:     block,
		blockSize: block.BlockSize(),
	}
}

func (enc encrypter) BlockSize() int {
	return enc.blockSize
}

func (enc encrypter) CryptBlocks(dst, src []byte) {
	for len(src) > 0 {
		enc.block.Encrypt(dst[:enc.blockSize], src[:enc.blockSize])
		src = src[enc.blockSize:]
		dst = dst[enc.blockSize:]
	}
}
