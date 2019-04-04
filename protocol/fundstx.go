package protocol

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"golang.org/x/crypto/ed25519"
)

const (
	FUNDSTX_SIZE = 213
)

//when we broadcast transactions we need a way to distinguish with a type

type FundsTx struct {
	Header 		byte
	Amount 		uint64
	Fee    		uint64
	TxCnt  		uint32
	From   		[32]byte
	To     		[32]byte
	Sig  		[64]byte
	Aggregated 	bool
	Data   		[]byte
}

func ConstrFundsTx(header byte, amount uint64, fee uint64, txCnt uint32, from, to [32]byte, sigKey ed25519.PrivateKey, data []byte) (tx *FundsTx, err error) {
	tx = new(FundsTx)

	tx.Header = header
	tx.From = from
	tx.To = to
	tx.Amount = amount
	tx.Fee = fee
	tx.TxCnt = txCnt
	tx.Aggregated = false
	tx.Data = data

	txHash := tx.Hash()
	signature := ed25519.Sign(sigKey, txHash[:])
	if signature == nil {
		return tx, nil
	}
	copy(tx.Sig[:], signature[:])

	return tx, nil
}

func (tx *FundsTx) Hash() (hash [32]byte) {
	if tx == nil {
		//is returning nil better?
		return [32]byte{}
	}

	txHash := struct {
		Header byte
		Amount uint64
		Fee    uint64
		TxCnt  uint32
		From   [32]byte
		To     [32]byte
		Data   []byte
	}{
		tx.Header,
		tx.Amount,
		tx.Fee,
		tx.TxCnt,
		tx.From,
		tx.To,
		tx.Data,
	}

	return SerializeHashContent(txHash)
}

//when we serialize the struct with binary.Write, unexported field get serialized as well, undesired
//behavior. Therefore, writing own encoder/decoder
func (tx *FundsTx) Encode() (encodedTx []byte) {
	// Encode
	encodeData := FundsTx{
		Header: tx.Header,
		Amount: tx.Amount,
		Fee:    tx.Fee,
		TxCnt:  tx.TxCnt,
		From:   tx.From,
		To:     tx.To,
		Sig:   	tx.Sig,
		Data:   tx.Data,
	}
	buffer := new(bytes.Buffer)
	gob.NewEncoder(buffer).Encode(encodeData)
	return buffer.Bytes()
}

func (*FundsTx) Decode(encodedTx []byte) *FundsTx {
	var decoded FundsTx
	buffer := bytes.NewBuffer(encodedTx)
	decoder := gob.NewDecoder(buffer)
	decoder.Decode(&decoded)
	return &decoded
}

func (tx *FundsTx) TxFee() uint64 { return tx.Fee }
func (tx *FundsTx) Size() uint64  { return FUNDSTX_SIZE }

func (tx *FundsTx) Sender() [32]byte { return tx.From }
func (tx *FundsTx) Receiver() [32]byte { return tx.To }

func (tx FundsTx) String() string {
	return fmt.Sprintf(
		"\nHeader: %v\n"+
			"Amount: %v\n"+
			"Fee: %v\n"+
			"TxCnt: %v\n"+
			"From: %x\n"+
			"To: %x\n"+
			"Sig: %x\n"+
			"Data: %v\n",
		tx.Header,
		tx.Amount,
		tx.Fee,
		tx.TxCnt,
		tx.From[0:8],
		tx.To[0:8],
		tx.Sig[0:8],
		tx.Data,
	)
}
