package types

import (
	"Blocker/crypto"
	"Blocker/proto"
	"Blocker/util"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewTransaction(t *testing.T) {
	ourPrivateKey := crypto.GeneratePrivateKey()
	ourPublicKey := ourPrivateKey.Public()
	// NOT know in the real world
	destinePrivateKey := crypto.GeneratePrivateKey()
	destinePublicKey := destinePrivateKey.Public()

	input := &proto.TxInput{
		PrevHash:     util.RandomHash(),
		PrevOutIndex: 0,
		PublicKey:    ourPublicKey.Bytes(),
	}

	output1 := &proto.TxOutput{
		Address: destinePublicKey.Address().Bytes(),
		Amount:  10,
	}

	output2 := &proto.TxOutput{
		Address: ourPublicKey.Address().Bytes(),
		Amount:  90,
	}

	tx := &proto.Transaction{
		Version: 1,
		Inputs:  []*proto.TxInput{input},
		Outputs: []*proto.TxOutput{output1, output2},
	}

	signature := SignTransaction(ourPrivateKey, tx)
	input.Signature = signature.Bytes()
	// This is false, since we first hash the no-signature version of the tx
	// then add the signature to the tx.
	assert.True(t, VerifyTransaction(tx))
}
