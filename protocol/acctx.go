package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"golang.org/x/crypto/ed25519"
)

const (
	ACCTX_SIZE = 169
)

type AccTx struct {
	Header            byte
	Issuer            [32]byte
	Fee               uint64
	PubKey            [32]byte
	Sig               [64]byte
	Contract          []byte
	ContractVariables []ByteArray
}

func ConstrAccTx(header byte, fee uint64, address [32]byte, rootPrivKey ed25519.PrivateKey, contract []byte, contractVariables []ByteArray) (tx *AccTx, newAccAddress ed25519.PublicKey, err error) {
	tx = new(AccTx)
	tx.Header = header
	tx.Fee = fee
	tx.Contract = contract
	tx.ContractVariables = contractVariables

	if address != [32]byte{} {
		copy(tx.PubKey[:], address[:])
	} else {
		var newAccAddressString string
		//Check if string representation of account address is 128 long. Else there will be problems when doing REST calls.
		for len(newAccAddressString) != 32 {
			//newAccAddress, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			newAccAddress, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil{
				return nil, nil, err
			}
			copy(tx.PubKey[:], newAccAddress[:])

			newAccAddressString = string(newAccAddress[:])
		}
	}

	var rootPublicKey [32]byte
	copy(rootPublicKey[:], rootPrivKey[32:])

	issuer := SerializeHashContent(rootPublicKey)
	copy(tx.Issuer[:], issuer[:])

	txHash := tx.Hash()

	sign:= ed25519.Sign(rootPrivKey, txHash[:])
	copy(tx.Sig[:], sign)

	return tx, newAccAddress, nil
}

func (tx *AccTx) Hash() [32]byte {
	if tx == nil {
		return [32]byte{}
	}

	txHash := struct {
		Header            byte
		Issuer            [32]byte
		Fee               uint64
		PubKey            [32]byte
		Contract          []byte
		ContractVariables []ByteArray
	}{
		tx.Header,
		tx.Issuer,
		tx.Fee,
		tx.PubKey,
		tx.Contract,
		tx.ContractVariables,
	}

	return SerializeHashContent(txHash)
}

func (tx *AccTx) Encode() []byte {
	if tx == nil {
		return nil
	}

	encoded := AccTx{
		Header: tx.Header,
		Issuer: tx.Issuer,
		Fee:    tx.Fee,
		PubKey: tx.PubKey,
		Sig:    tx.Sig,
	}

	buffer := new(bytes.Buffer)
	gob.NewEncoder(buffer).Encode(encoded)
	return buffer.Bytes()
}

func (*AccTx) Decode(encoded []byte) (tx *AccTx) {
	var decoded AccTx
	buffer := bytes.NewBuffer(encoded)
	decoder := gob.NewDecoder(buffer)
	decoder.Decode(&decoded)
	return &decoded
}

func (tx *AccTx) TxFee() uint64 { return tx.Fee }

func (tx *AccTx) Size() uint64 { return ACCTX_SIZE }

func (tx *AccTx) Sender() [32]byte { return tx.Issuer}
func (tx *AccTx) Receiver() [32]byte { return [32]byte{}}


func (tx AccTx) String() string {
	return fmt.Sprintf(
		"\n"+
			"Header: %x\n"+
			"Issuer: %x\n"+
			"Fee: %v\n"+
			"PubKey: %x\n"+
			"Sig: %x\n"+
			"Contract: %v\n"+
			"ContractVariables: %v\n",
		tx.Header,
		tx.Issuer[0:8],
		tx.Fee,
		tx.PubKey[0:8],
		tx.Sig[0:8],
		tx.Contract[:],
		tx.ContractVariables[:],
	)
}
