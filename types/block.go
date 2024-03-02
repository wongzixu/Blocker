package types

import (
	"Blocker/crypto"
	"Blocker/proto"
	"crypto/sha256"
)
import pb "github.com/golang/protobuf/proto"

// HashBlock hashes a block, but just the header, using SHA256.
func HashBlock(block *proto.Block) []byte {
	bytes, err := pb.Marshal(block)
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256(bytes)
	return hash[:]
}

func SignBlock(pk *crypto.PrivateKey, block *proto.Block) *crypto.Signature {
	return pk.Sign(HashBlock(block))
}
