package crypto

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	privateKey := GeneratePrivateKey()
	assert.Equal(t, len(privateKey.Bytes()), privateKeySize)
	publicKey := privateKey.Public()
	assert.Equal(t, len(publicKey.Bytes()), publicKeySize)
}

func TestPrivateKeySign(t *testing.T) {
	validPrivateKey := GeneratePrivateKey()
	validPublicKey := validPrivateKey.Public()
	message := []byte("Hello, world!")
	signature := validPrivateKey.Sign(message)

	// test for the valid signature
	assert.True(t, signature.Verify(validPublicKey, message))

	// test for the invalid signature
	invalidPrivateKey := GeneratePrivateKey()
	invalidPublicKey := invalidPrivateKey.Public()
	assert.False(t, signature.Verify(invalidPublicKey, message))

	// test for the invalid message
	invalidMessage := []byte("Hello, world")
	assert.False(t, signature.Verify(validPublicKey, invalidMessage))
}
