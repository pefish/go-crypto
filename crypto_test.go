package p_crypto

import (
	"fmt"
	"testing"
)

func TestCryptoClass_Sha256ToHex(t *testing.T) {
	if Crypto.Sha256ToHex(`12123`) != `c492e2a3e4f6cc9c5b3a1ae173333905d4cf6407f1c3b87c50763bbbbadc0dd9` {
		t.Error()
	}
}

func TestCryptoClass_ShiftCryptForInt(t *testing.T) {
	if 79456702 != Crypto.ShiftCryptForInt(79456732, 70) {
		t.Error()
	}
}

func TestCryptoClass_GeneRsaKeyPair(t *testing.T) {
	fmt.Println(Crypto.GeneRsaKeyPair())
}

func TestCryptoClass_AesCbcEncrypt(t *testing.T) {
	if `bj7P4lrG3TyB8KBpCDyGqQ==` != Crypto.AesCbcEncrypt(`1234567890123456`, `haha`) {
		t.Error()
	}
}

func TestCryptoClass_AesCbcDecrypt(t *testing.T) {
	if `haha` != Crypto.AesCbcDecrypt(`1234567890123456`, `bj7P4lrG3TyB8KBpCDyGqQ==`) {
		t.Error()
	}
}
