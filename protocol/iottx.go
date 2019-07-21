package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
	"unsafe"
)

//when we broadcast transactions we need a way to distinguish with a type

type IotTx struct {
	Header byte
	TxCnt  uint32
	From   [32]byte
	To     [32]byte
	Sig    [64]byte
	Data   []byte
	Fee    uint64
}

func ConstrIotTx(header byte, fee uint64, txCnt uint32, from, to [32]byte, sigKey ed25519.PrivateKey, data []byte) (tx *IotTx, err error) {
	tx = new(IotTx)
	tx.Header = header
	tx.Fee = tx.TxFee()
	tx.From = from
	tx.To = to
	tx.TxCnt = txCnt
	tx.Data = data
	txHash := tx.Hash()

	signature := ed25519.Sign(sigKey, txHash[:])
	if signature == nil {
		return tx, nil
	}
	copy(tx.Sig[:], signature[:])

	return tx, nil
}

func (tx *IotTx) Hash() (hash [32]byte) {
	//Order -> To From txCnt txFee Header data
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, tx.To)
	binary.Write(buf, binary.BigEndian, tx.From)
	binary.Write(buf, binary.BigEndian, tx.TxCnt)
	binary.Write(buf, binary.BigEndian, tx.TxFee())
	binary.Write(buf, binary.BigEndian, tx.Header)
	binary.Write(buf, binary.BigEndian, tx.Data)
	return sha3.Sum256(buf.Bytes())
}

//when we serialize the struct with binary.Write, unexported field get serialized as well, undesired
//behavior. Therefore, writing own encoder/decoder
func (tx *IotTx) Encode() (encodedTx []byte) {

	if tx == nil {
		return nil
	}

	// Encode
	encodeData := IotTx{
		tx.Header,
		tx.TxCnt,
		tx.From,
		tx.To,
		tx.Sig,
		tx.Data,
		tx.Fee,
	}
	buffer := new(bytes.Buffer)
	gob.NewEncoder(buffer).Encode(encodeData)

	return buffer.Bytes()
}

func (*IotTx) Decode(encodedTx []byte) *IotTx {
	var decoded IotTx
	buffer := bytes.NewBuffer(encodedTx)
	decoder := gob.NewDecoder(buffer)
	decoder.Decode(&decoded)
	return &decoded
}

func (tx IotTx) String() string {
	return fmt.Sprintf(
		"\nHeader: %v\n"+
			"TxCnt: %v\n"+
			"From: %x\n"+
			"To: %x\n"+
			"Sig: %x\n"+
			"Data: %v\n"+
			"Fee: %v\n",

		tx.Header,
		tx.TxCnt,
		tx.From[0:8],
		tx.To[0:8],
		tx.Sig[0:8],
		tx.Data,
		tx.Fee,
	)
}

func (tx *IotTx) Size() uint64 {
	size := int(unsafe.Sizeof(*tx)) + len(tx.Data)
	return uint64(size)
}
func (tx *IotTx) TxFee() uint64 { return tx.Fee }

func (tx *IotTx) Sender() [32]byte   { return [32]byte{} } //Return empty because never needed.
func (tx *IotTx) Receiver() [32]byte { return [32]byte{} }
