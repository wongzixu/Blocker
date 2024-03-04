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

func TestNewPrivateKeyFromString(t *testing.T) {
	var (
		seedString    = "6ccb38af8bb221e9ed2ffc05a0ef090c58abfd7a19646254c49170a3127f4915"
		privateKey    = GeneratePrivateKeyWithString(seedString)
		addressString = "09065fb49bbbfe6db0f9211925be3a1cfde27ff8"
	)

	assert.Equal(t, len(privateKey.Bytes()), privateKeySize)
	address := privateKey.Public().Address()
	assert.Equal(t, address.String(), addressString)

}

func TestPrivateKeySign(t *testing.T) {
	validPrivateKey := GeneratePrivateKey()
	validPublicKey := validPrivateKey.Public()
	message := []byte("Hello, world!")
	signature := validPrivateKey.Sign(message)

	// test for the valid signature
	assert.True(t, signature.Verify(validPublicKey, message))
	assert.True(t, signature.Verify(validPublicKey, message))

	// test for the invalid signature
	invalidPrivateKey := GeneratePrivateKey()
	invalidPublicKey := invalidPrivateKey.Public()
	assert.False(t, signature.Verify(invalidPublicKey, message))

	// test for the invalid message
	invalidMessage := []byte("Hello, world")
	assert.False(t, signature.Verify(validPublicKey, invalidMessage))
}

func TestPublicKeyAddress(t *testing.T) {
	publicKey := GeneratePrivateKey().Public()
	assert.Equal(t, len(publicKey.Address().Bytes()), addressSize)
}
