package go_crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"strconv"

	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

type CryptoType struct {
}

var CryptoInstance = New()

func New() *CryptoType {
	return &CryptoType{}
}

func (ct *CryptoType) Sha256ToHex(str string) string {
	h := sha256.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

func (ct *CryptoType) MustHmacSha256ToHex(str string, secret string) string {
	result, err := ct.HmacSha256ToHex(str, secret)
	if err != nil {
		panic(err)
	}
	return result
}

func (ct *CryptoType) HmacSha256ToHex(str string, secret string) (string, error) {
	h := hmac.New(sha256.New, []byte(secret))
	_, err := io.WriteString(h, str)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (ct *CryptoType) Sha256ToBytes(str string) []byte {
	h := sha256.New()
	h.Write([]byte(str))
	return h.Sum(nil)
}

func (ct *CryptoType) Md5ToHex(str string) string {
	data := []byte(str)
	has := md5.Sum(data)
	return fmt.Sprintf("%x", has)
}

/*
*
移位加密
*/
func (ct *CryptoType) ShiftCryptForInt(shiftCode int64, target int64) (int64, error) {
	shiftCodeStr := strconv.FormatInt(shiftCode, 10)
	targetStr := strconv.FormatInt(target, 10)
	length := len(shiftCodeStr)
	targetLength := len(targetStr)
	result := ``
	for i := 0; i < length-targetLength; i++ {
		result += string(shiftCodeStr[i])
	}
	resultLength := len(result)
	for i := 0; i < targetLength; i++ {
		targetIInt, err := strconv.ParseInt(string(targetStr[i]), 10, 64)
		if err != nil {
			return 0, err
		}
		shiftCodeIInt, err := strconv.ParseInt(string(shiftCodeStr[i+resultLength]), 10, 64)
		if err != nil {
			return 0, err
		}
		result += strconv.FormatInt((targetIInt+shiftCodeIInt)%10, 10)
	}
	resultInt, err := strconv.ParseInt(result, 10, 64)
	if err != nil {
		return 0, err
	}
	return resultInt, nil
}

func (ct *CryptoType) PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func (ct *CryptoType) PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func (ct *CryptoType) MustAesCbcEncrypt(key string, data string) string {
	result, err := ct.AesCbcEncrypt(key, data)
	if err != nil {
		panic(err)
	}
	return result
}

// aes加密，填充秘钥key的16位，24,32分别对应AES-128, AES-192, or AES-256.
func (ct *CryptoType) AesCbcEncrypt(key string, data string) (string, error) {
	length := len(key)
	newKey := key
	var err error
	if length <= 16 {
		newKey, err = ct.SpanLeft(key, 16, `0`)
	} else if length <= 24 {
		newKey, err = ct.SpanLeft(key, 24, `0`)
	} else if length <= 32 {
		newKey, err = ct.SpanLeft(key, 32, `0`)
	} else {
		return "", errors.New(`Length of secret key error.`)
	}

	keyBytes := []byte(newKey)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	origData := ct.PKCS5Padding([]byte(data), blockSize)
	blockMode := cipher.NewCBCEncrypter(block, make([]byte, blockSize)) // 使用``作为iv
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return base64.StdEncoding.EncodeToString(crypted), nil
}

func (ct *CryptoType) MustAesCbcDecrypt(key string, data string) string {
	result, err := ct.AesCbcDecrypt(key, data)
	if err != nil {
		panic(err)
	}
	return result
}

func (ct *CryptoType) AesCbcDecrypt(key string, data string) (string, error) {
	length := len(key)
	newKey := key
	var err error
	if length <= 16 {
		newKey, err = ct.SpanLeft(key, 16, `0`)
	} else if length <= 24 {
		newKey, err = ct.SpanLeft(key, 24, `0`)
	} else if length <= 32 {
		newKey, err = ct.SpanLeft(key, 32, `0`)
	} else {
		return "", errors.New(`Length of secret key error.`)
	}

	block, err := aes.NewCipher([]byte(newKey))
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, make([]byte, blockSize))
	crypted, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = ct.PKCS5UnPadding(origData)
	return string(origData), nil
}

func (ct *CryptoType) MustGeneRsaKeyPair(params ...int) (priv string, pub string) {
	result1, result2, err := ct.GeneRsaKeyPair(params...)
	if err != nil {
		panic(err)
	}
	return result1, result2
}

func (ct *CryptoType) GeneRsaKeyPair(params ...int) (priv string, pub string, err error) {
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
		return "", "", err
	}
	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	pubBuffer := new(bytes.Buffer)
	err = pem.Encode(pubBuffer, block)
	if err != nil {
		return "", "", err
	}
	return privBuffer.String(), pubBuffer.String(), nil
}

func (ct *CryptoType) MustSpanLeft(str string, length int, fillChar string) string {
	result, err := ct.SpanLeft(str, length, fillChar)
	if err != nil {
		panic(err)
	}
	return result
}

func (ct *CryptoType) SpanLeft(str string, length int, fillChar string) (string, error) {
	if len(str) > length {
		return "", errors.New(`Length is too small.`)
	}
	if len(fillChar) != 1 {
		return "", errors.New(`Length of fillChar must be 1.`)
	}
	result := ``
	for i := 0; i < length-len(str); i++ {
		result += fillChar
	}
	return result + str, nil
}

func (ct *CryptoType) MustBcryptToDbPass(passwdInput string) string {
	result, err := ct.BcryptToDbPass(passwdInput)
	if err != nil {
		panic(err)
	}
	return result
}

func (ct *CryptoType) BcryptToDbPass(passwdInput string) (string, error) {
	hashPasswdInput := md5.New()
	hashPasswdInput.Write([]byte(passwdInput))
	passwdBcryptBytes, err := bcrypt.GenerateFromPassword([]byte(fmt.Sprintf("%x", hashPasswdInput.Sum(nil))), bcrypt.MinCost)
	if err != nil {
		return "", err
	}

	return string(passwdBcryptBytes), nil
}

func (ct *CryptoType) VerifyBcryptDbPass(passwdInput string, passwdInDb string) bool {
	hs := md5.New()
	hs.Write([]byte(passwdInput))

	err := bcrypt.CompareHashAndPassword(
		[]byte(passwdInDb),
		[]byte(fmt.Sprintf("%x", hs.Sum(nil))),
	)
	return err == nil
}

func (ct *CryptoType) EncryptRc4(input string, pass string) (string, error) {
	if len(input) <= 0 {
		return "", errors.New("input string error")
	}
	if len(pass) <= 0 {
		return "", errors.New("pass string error")
	}
	c, err := rc4.NewCipher([]byte(pass))
	if err != nil {
		return "", err
	}
	src := []byte(input)
	dst := make([]byte, len(src))
	c.XORKeyStream(dst, src)
	return hex.EncodeToString(dst), nil
}

func (ct *CryptoType) DecryptRc4(input string, pass string) (string, error) {
	if len(input) <= 0 {
		return "", errors.New("input string error")
	}
	if len(pass) <= 0 {
		return "", errors.New("pass string error")
	}
	c, err := rc4.NewCipher([]byte(pass))
	if err != nil {
		return "", err
	}
	inputBytes, err := hex.DecodeString(input)
	if err != nil {
		return "", err
	}
	dst := make([]byte, len(inputBytes))
	c.XORKeyStream(dst, inputBytes)
	return string(dst), nil
}
