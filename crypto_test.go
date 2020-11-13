package go_crypto

import (
	"github.com/pefish/go-test-assert"
	"strings"
	"testing"
)

func TestCryptoClass_Sha256ToHex(t *testing.T) {
	test.Equal(t, "c492e2a3e4f6cc9c5b3a1ae173333905d4cf6407f1c3b87c50763bbbbadc0dd9", Crypto.Sha256ToHex(`12123`))
}

func TestCryptoClass_ShiftCryptForInt(t *testing.T) {
	test.Equal(t, int64(79456702), Crypto.ShiftCryptForInt(79456732, 70))
}

func TestCryptoClass_GeneRsaKeyPair(t *testing.T) {
	priv, pubk := Crypto.MustGeneRsaKeyPair()
	test.Equal(t, true, strings.HasPrefix(priv, "-----BEGIN RSA PRIVATE KEY-----"))
	test.Equal(t, true, strings.HasPrefix(pubk, "-----BEGIN PUBLIC KEY-----"))
}

func TestCryptoClass_AesCbcEncrypt(t *testing.T) {
	test.Equal(t, "bj7P4lrG3TyB8KBpCDyGqQ==", Crypto.MustAesCbcEncrypt(`1234567890123456`, `haha`))
}

func TestCryptoClass_AesCbcDecrypt(t *testing.T) {
	test.Equal(t, "haha", Crypto.MustAesCbcDecrypt(`1234567890123456`, `bj7P4lrG3TyB8KBpCDyGqQ==`))
}

func TestCryptoClass_HmacSha256ToHex(t *testing.T) {
	type args struct {
		str    string
		secret string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: `test`,
			args: args{
				str:    `625422`,
				secret: `test`,
			},
			want: `9cb8d8c168d20c0bd03782acbda3dfa504fcac3be2b80176134b89f54e376dd5`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Crypto.MustHmacSha256ToHex(tt.args.str, tt.args.secret); got != tt.want {
				t.Errorf("CryptoClass.HmacSha256ToHex() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCryptoClass_EncryptRc4(t *testing.T) {
	result, err := Crypto.EncryptRc4("gFkFZafUbcO/4Lg5bxhpUGQECZHPfGzX4t8pKcT7+3s=", "dhshrsyhwrthwyrhwgnwyt")
	test.Equal(t, nil, err)
	test.Equal(t, "316ca67cf2ccf6d5feb976176c016ee23adca4ee5506e712b49cd293d55766759c4f4175e9246c58a952de95", result)
}

func TestCryptoClass_DecryptRc4(t *testing.T) {
	result, err := Crypto.DecryptRc4("316ca67cf2ccf6d5feb976176c016ee23adca4ee5506e712b49cd293d55766759c4f4175e9246c58a952de95", "dhshrsyhwrthwyrhwgnwyt")
	test.Equal(t, nil, err)
	test.Equal(t, "gFkFZafUbcO/4Lg5bxhpUGQECZHPfGzX4t8pKcT7+3s=", result)
}