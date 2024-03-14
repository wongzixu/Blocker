package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
)

const (
	privateKeySize  = ed25519.PrivateKeySize
	publicKeySize   = ed25519.PublicKeySize
	seedSize        = 32
	addressSize     = 20
	signatureLength = 64
)

type PrivateKey struct {
	key ed25519.PrivateKey
}

type PublicKey struct {
	key ed25519.PublicKey
}

func GeneratePrivateKeyWithString(seed string) *PrivateKey {
	bytes, err := hex.DecodeString(seed)
	if err != nil {
		panic(err)
	}
	return GeneratePrivateKeyWithSeed(bytes)
}

func GeneratePrivateKeyWithSeed(seed []byte) *PrivateKey {
	if len(seed) != seedSize {
		panic("Invalid seed size, seed size must be 32 bytes long.")
	}
	return &PrivateKey{ed25519.NewKeyFromSeed(seed)}
}

func GeneratePrivateKey() *PrivateKey {
	seed := make([]byte, seedSize)

	_, err := io.ReadFull(rand.Reader, seed)
	if err != nil {
		panic(err)
	}

	return &PrivateKey{ed25519.NewKeyFromSeed(seed)}
}

func PublicKeyFromBytes(b []byte) *PublicKey {
	if len(b) != publicKeySize {
		panic("The public key size is wrong, if in verify non-valid verify")
	}
	return &PublicKey{
		key: b,
	}
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

func (p *PublicKey) Address() Address {
	return Address{p.key[len(p.key)-addressSize:]}
}

type Address struct {
	value []byte
}

func (a Address) Bytes() []byte {
	return a.value
}

func (a Address) String() string {
	return hex.EncodeToString(a.value)
}

type Signature struct {
	value []byte
}

func (s *Signature) Verify(publicKey *PublicKey, message []byte) bool {
	return ed25519.Verify(publicKey.key, message, s.value)
}

func (s *Signature) Bytes() []byte {
	return s.value
}

func SignatureFromBytes(b []byte) *Signature {
	if len(b) != signatureLength {
		panic("The length of the bytes should be equal to 64")
	}
	return &Signature{
		value: b,
	}
}
