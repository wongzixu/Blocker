package types

import (
	"Blocker/crypto"
	"Blocker/util"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHashBlock(t *testing.T) {
	block := util.RandomBlock()
	hash := HashBlock(block)
	assert.Equal(t, len(hash), 32)
}

func TestSignBlock(t *testing.T) {
	privateKey := crypto.GeneratePrivateKey()
	publickKey := privateKey.Public()
	block := util.RandomBlock()
	signature := SignBlock(privateKey, block)
	// Verify the signature
	assert.True(t, signature.Verify(publickKey, HashBlock(block)))
}
