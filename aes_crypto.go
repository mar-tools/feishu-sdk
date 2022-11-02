package feishu

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

func AESDecrypt(base64CipherText string, key []byte) (unpadDecrypted []byte, err error) {
	sum := sha256.Sum256(key)

	key = sum[:]

	cipherText, err := base64.StdEncoding.DecodeString(base64CipherText)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	if len(cipherText) < aes.BlockSize {
		err = errors.New("len(crypt) < aes.BlockSize")
		return
	}
	cbc := cipher.NewCBCDecrypter(block, cipherText[:aes.BlockSize])
	cipherText = cipherText[aes.BlockSize:]
	decrypted := make([]byte, len(cipherText))
	cbc.CryptBlocks(decrypted, cipherText)

	unpadDecrypted = PKCS5Trimming(decrypted)
	return
}

func PKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}
