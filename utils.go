package jwtE

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

const (
	HalfDay    = time.Hour * 12
	OneDay     = HalfDay * 2
	OneWeek    = OneDay * 7
	OneMonth   = OneDay * 30
	OneQuarter = OneMonth * 3
	OneYear    = OneQuarter * 4
)

func NewExpiresTime(t time.Duration) time.Time {
	return time.Now().Add(t)
}

func base64encode(a any) (res string, err error) {
	temp, err := json.Marshal(a)
	if err != nil {
		return
	}
	return base64.RawURLEncoding.EncodeToString(temp), nil
}

func base64decode[T interface{}](a string) (res T, err error) {
	temp, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil {
		return
	}
	err = json.Unmarshal(temp, &res)
	return
}

func hmacWithSha256(a any, sec []byte) (res string, err error) {
	temp, err := json.Marshal(a)
	if err != nil {
		return
	}
	h := hmac.New(sha256.New, sec)
	_, err = h.Write(temp)
	if err != nil {
		return
	}
	res = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return
}

func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}

func pkcs7Unpadding(b []byte) []byte {
	length := len(b)
	uL := int(b[length-1])
	return b[:(length - uL)]
}

func aesEncrypt(a any, key []byte) (string, error) {
	temp, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	temp = pkcs7Padding(temp, block.BlockSize())
	iv := bytes.Repeat([]byte("6"), 16)
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(temp))
	mode.CryptBlocks(ciphertext, temp)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func aesDecrypt[T interface{}](a string, key []byte) (res T, err error) {
	temp, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil {
		return
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	iv := bytes.Repeat([]byte("6"), 16)
	mode := cipher.NewCBCDecrypter(block, iv)
	ciphertext := make([]byte, len(temp))
	mode.CryptBlocks(ciphertext, temp)
	temp = pkcs7Unpadding(ciphertext)
	err = json.Unmarshal(temp, &res)
	return
}

func strMd5(s string) []byte {
	h := md5.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}
