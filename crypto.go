package go_crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/pefish/go-reflect"
	"golang.org/x/crypto/bcrypt"
	"io"
)

type CryptoClass struct {
}

var Crypto = CryptoClass{}

func (cryptoInstance *CryptoClass) Sha256ToHex(str string) string {
	h := sha256.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

func (cryptoInstance *CryptoClass) MustHmacSha256ToHex(str string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	_, err := io.WriteString(h, str)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (cryptoInstance *CryptoClass) Sha256ToBytes(str string) []byte {
	h := sha256.New()
	h.Write([]byte(str))
	return h.Sum(nil)
}

func (cryptoInstance *CryptoClass) Md5ToHex(str string) string {
	data := []byte(str)
	has := md5.Sum(data)
	return fmt.Sprintf("%x", has)
}

/**
移位加密
*/
func (cryptoInstance *CryptoClass) ShiftCryptForInt(shiftCode int64, target int64) int64 {
	shiftCodeStr := go_reflect.Reflect.ToString(shiftCode)
	targetStr := go_reflect.Reflect.ToString(target)
	length := len(shiftCodeStr)
	targetLength := len(targetStr)
	result := ``
	for i := 0; i < length-targetLength; i++ {
		result += string(shiftCodeStr[i])
	}
	resultLength := len(result)
	for i := 0; i < targetLength; i++ {
		temp := (go_reflect.Reflect.MustToInt64(string(targetStr[i])) + go_reflect.Reflect.MustToInt64(string(shiftCodeStr[i+resultLength]))) % 10
		result += go_reflect.Reflect.ToString(temp)
	}
	return go_reflect.Reflect.MustToInt64(result)
}

func (cryptoInstance *CryptoClass) PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func (cryptoInstance *CryptoClass) PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// aes加密，填充秘钥key的16位，24,32分别对应AES-128, AES-192, or AES-256.
func (cryptoInstance *CryptoClass) MustAesCbcEncrypt(key string, data string) string {
	length := len(key)
	if length <= 16 {
		key = cryptoInstance.mustSpanLeft(key, 16, `0`)
	} else if length <= 24 {
		key = cryptoInstance.mustSpanLeft(key, 24, `0`)
	} else if length <= 32 {
		key = cryptoInstance.mustSpanLeft(key, 32, `0`)
	} else {
		panic(`length of secret key error`)
	}

	keyBytes := []byte(key)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		panic(err)
	}
	blockSize := block.BlockSize()
	origData := cryptoInstance.PKCS5Padding([]byte(data), blockSize)
	blockMode := cipher.NewCBCEncrypter(block, make([]byte, blockSize)) // 使用``作为iv
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return base64.StdEncoding.EncodeToString(crypted)
}

func (cryptoInstance *CryptoClass) MustAesCbcDecrypt(key string, data string) string {
	length := len(key)
	if length <= 16 {
		key = cryptoInstance.mustSpanLeft(key, 16, `0`)
	} else if length <= 24 {
		key = cryptoInstance.mustSpanLeft(key, 24, `0`)
	} else if length <= 32 {
		key = cryptoInstance.mustSpanLeft(key, 32, `0`)
	} else {
		panic(`length of secret key error`)
	}

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
	origData = cryptoInstance.PKCS5UnPadding(origData)
	return string(origData)
}

func (cryptoInstance *CryptoClass) MustGeneRsaKeyPair(params ...int) (string, string) {
	bits := 2048
	if len(params) > 0 {
		bits = params[0]
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	privBuffer := new(bytes.Buffer)
	err = pem.Encode(privBuffer, block)
	if err != nil {
		panic(err)
	}
	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	pubBuffer := new(bytes.Buffer)
	err = pem.Encode(pubBuffer, block)
	if err != nil {
		panic(err)
	}
	return privBuffer.String(), pubBuffer.String()
}

func (cryptoInstance *CryptoClass) mustSpanLeft(str string, length int, fillChar string) string {
	if len(str) > length {
		panic(errors.New(`length is too small`))
	}
	if len(fillChar) != 1 {
		panic(errors.New(`length of fillChar must be 1`))
	}
	result := ``
	for i := 0; i < length-len(str); i++ {
		result += fillChar
	}
	return result + str
}

func (cryptoInstance *CryptoClass) MustBcryptToDbPass(passwdInput string) string {
	hashPasswdInput := md5.New()
	hashPasswdInput.Write([]byte(passwdInput))
	passwdBcryptBytes, err := bcrypt.GenerateFromPassword([]byte(fmt.Sprintf("%x", hashPasswdInput.Sum(nil))), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}

	return string(passwdBcryptBytes)
}

func (cryptoInstance *CryptoClass) VerifyBcryptDbPass(passwdInput string, passwdInDb string) bool {
	hs := md5.New()
	hs.Write([]byte(passwdInput))

	err := bcrypt.CompareHashAndPassword([]byte(passwdInDb), []byte(fmt.Sprintf("%x", hs.Sum(nil))))
	return err == nil
}
