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

// NewTransaction function will return a transaction block. At most of the time
// the transaction will contain one input and two output.
//
// The signature for the whole transaction is applied to all inputs
func NewTransaction(inputs []*proto.TxInput, outputs []*proto.TxOutput, version int32) *proto.Transaction {
	return &proto.Transaction{
		Version: version,
		Inputs:  inputs,
		Outputs: outputs,
	}
}

func VerifyTransaction(tx *proto.Transaction) bool {
	for _, input := range tx.Inputs {
		sig := crypto.SignatureFromBytes(input.Signature)
		publicKey := crypto.PublicKeyFromBytes(input.PublicKey)
		// TODO: This is just a trike thing, need to be fixed later on.
		input.Signature = nil
		if !sig.Verify(publicKey, HashTransaction(tx)) {
			return false
		}
	}
	return true
}
