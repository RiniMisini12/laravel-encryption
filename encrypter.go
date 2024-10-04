package encrypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"strings"

	"github.com/elliotchance/phpserialize"
)

func PKCS7Padding(data []byte, blockSize int) []byte {
	paddingSize := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(data, padding...)
}

func PKCS7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid padding size")
	}
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.New("unpadding size is larger than data size")
	}
	return data[:(length - unpadding)], nil
}

func EncryptArray(array interface{}, key string) (string, error) {
	serializedArray, err := phpserialize.Marshal(array, nil)
	if err != nil {
		return "", errors.New("could not serialize array")
	}

	serializedArrayString := string(serializedArray)
	log.Println("Serialized array:", serializedArrayString)

	return EncryptString(serializedArrayString, key)
}

func DecryptArray(encryptedText, key string) (map[interface{}]interface{}, error) {
	decryptedText, err := DecryptString(encryptedText, key)
	if err != nil {
		return nil, err
	}

	log.Println("Decrypted text:", decryptedText)

	var array map[interface{}]interface{}
	err = phpserialize.Unmarshal([]byte(decryptedText), &array)
	if err != nil {
		return nil, errors.New("could not unserialize array")
	}

	return array, nil
}

func EncryptString(plainText, key string) (string, error) {
	appKeyClean := strings.TrimPrefix(key, "base64:")

	appKeyDecoded, err := base64.StdEncoding.DecodeString(appKeyClean)
	if err != nil {
		return "", errors.New("could not decode app key")
	}

	if len(appKeyDecoded) != 32 {
		return "", errors.New("key must be 32 bytes")
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	paddedText := PKCS7Padding([]byte(plainText), aes.BlockSize)

	block, err := aes.NewCipher(appKeyDecoded)
	if err != nil {
		return "", err
	}
	cipherText := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, paddedText)

	encodedIV := base64.StdEncoding.EncodeToString(iv)
	encodedCipherText := base64.StdEncoding.EncodeToString(cipherText)

	mac := hmac.New(sha256.New, appKeyDecoded)
	mac.Write([]byte(encodedIV + encodedCipherText))
	hmacValue := mac.Sum(nil)

	hexEncodedMAC := hex.EncodeToString(hmacValue)

	payload := map[string]string{
		"iv":    encodedIV,
		"value": encodedCipherText,
		"mac":   hexEncodedMAC,
		"tag":   "",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	encodedPayload := base64.StdEncoding.EncodeToString(jsonPayload)

	return encodedPayload, nil
}

func DecryptString(encryptedText, key string) (string, error) {
	appKeyClean := strings.TrimPrefix(key, "base64:")

	appKeyDecoded, err := base64.StdEncoding.DecodeString(appKeyClean)
	if err != nil {
		return "", errors.New("could not decode app key")
	}

	if len(appKeyDecoded) != 32 {
		return "", errors.New("key must be 32 bytes")
	}

	decodedPayload, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	payload := map[string]string{}
	err = json.Unmarshal(decodedPayload, &payload)
	if err != nil {
		return "", err
	}

	encodedIV := payload["iv"]
	encodedCipherText := payload["value"]
	encodedMAC := payload["mac"]

	mac := hmac.New(sha256.New, appKeyDecoded)
	mac.Write([]byte(encodedIV + encodedCipherText))
	expectedMAC := mac.Sum(nil)

	decodedMAC, err := hex.DecodeString(encodedMAC)
	if err != nil {
		return "", err
	}

	if !hmac.Equal(expectedMAC, decodedMAC) {
		return "", errors.New("the MAC is invalid")
	}

	iv, err := base64.StdEncoding.DecodeString(encodedIV)
	if err != nil {
		return "", err
	}

	cipherText, err := base64.StdEncoding.DecodeString(encodedCipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(appKeyDecoded)
	if err != nil {
		return "", err
	}

	if len(cipherText)%aes.BlockSize != 0 {
		return "", errors.New("cipherText length must be a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)

	plainText, err := PKCS7UnPadding(cipherText)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
