package crypto

import "crypto/ed25519"

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
