package p_crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/pefish/go-reflect"
)

type CryptoClass struct {
}

var Crypto = CryptoClass{}

func (this *CryptoClass) Sha256ToHex(str string) string {
	h := sha256.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

func (this *CryptoClass) Sha256ToBytes(str string) []byte {
	h := sha256.New()
	h.Write([]byte(str))
	return h.Sum(nil)
}

func (this *CryptoClass) Md5ToHex(str string) string {
	data := []byte(str)
	has := md5.Sum(data)
	return fmt.Sprintf("%x", has)
}

/**
移位加密
*/
func (this *CryptoClass) ShiftCryptForInt(shiftCode int64, target int64) int64 {
	shiftCodeStr := p_reflect.Reflect.ToString(shiftCode)
	targetStr := p_reflect.Reflect.ToString(target)
	length := len(shiftCodeStr)
	targetLength := len(targetStr)
	result := ``
	for i := 0; i < length-targetLength; i++ {
		result += string(shiftCodeStr[i])
	}
	resultLength := len(result)
	for i := 0; i < targetLength; i++ {
		temp := (p_reflect.Reflect.ToInt64(targetStr[i]) + p_reflect.Reflect.ToInt64(shiftCodeStr[i+resultLength])) % 10
		result += p_reflect.Reflect.ToString(temp)
	}
	return p_reflect.Reflect.ToInt64(result)
}

func (this *CryptoClass) PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func (this *CryptoClass) PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// aes加密，填充秘钥key的16位，24,32分别对应AES-128, AES-192, or AES-256.
func (this *CryptoClass) AesCbcEncrypt(key string, data string) string {
	keyBytes := []byte(key)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		panic(err)
	}
	blockSize := block.BlockSize()
	origData := this.PKCS5Padding([]byte(data), blockSize)
	blockMode := cipher.NewCBCEncrypter(block, make([]byte, blockSize)) // 使用``作为iv
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return base64.StdEncoding.EncodeToString(crypted)
}

func (this *CryptoClass) AesCbcDecrypt(key string, data string) string {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, make([]byte, blockSize))
	crypted, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		panic(err)
	}
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = this.PKCS5UnPadding(origData)
	return string(origData)
}
