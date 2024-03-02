package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
)

const (
	privateKeySize = ed25519.PrivateKeySize
	publicKeySize  = ed25519.PublicKeySize
	seedSize       = 32
)

type PrivateKey struct {
	key ed25519.PrivateKey
}

type PublicKey struct {
	key ed25519.PublicKey
}

func GeneratePrivateKey() *PrivateKey {
	seed := make([]byte, seedSize)

	_, err := io.ReadFull(rand.Reader, seed)
	if err != nil {
		panic(err)
	}

	return &PrivateKey{ed25519.NewKeyFromSeed(seed)}
}

func (p *PrivateKey) Bytes() []byte {
	return p.key
}

func (p *PrivateKey) Sign(message []byte) *Signature {
	return &Signature{ed25519.Sign(p.key, message)}
}

func (p *PrivateKey) Public() *PublicKey {
	pubKey := make([]byte, publicKeySize)
	copy(pubKey, p.key[32:])
	return &PublicKey{pubKey}
}

func (p *PublicKey) Bytes() []byte {
	return p.key
}

type Signature struct {
	value []byte
}

func (s *Signature) Bytes() []byte {
	return s.value
}

func (s *Signature) Verify(publicKey *PublicKey, message []byte) bool {
	return ed25519.Verify(publicKey.key, message, s.value)
}
