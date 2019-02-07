package p_crypto

import (
	"testing"
)

func TestCryptoClass_Sha256ToHex(t *testing.T) {
	if Crypto.Sha256ToHex(`12123`) != `c492e2a3e4f6cc9c5b3a1ae173333905d4cf6407f1c3b87c50763bbbbadc0dd9` {
		t.Error()
	}
}
