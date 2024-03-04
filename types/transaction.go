package types

import (
	"Blocker/crypto"
	"Blocker/proto"
	"crypto/sha256"
)
import pb "github.com/golang/protobuf/proto"

func HashTransaction(tx *proto.Transaction) []byte {
	b, err := pb.Marshal(tx)
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256(b)
	return hash[:]
}

func SignTransaction(key *crypto.PrivateKey, tx *proto.Transaction) *crypto.Signature {
	return key.Sign(HashTransaction(tx))
}
