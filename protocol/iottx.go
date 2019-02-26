package protocol

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"golang.org/x/crypto/ed25519"
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
}

func ConstrIotTx(header byte, txCnt uint32, from, to [32]byte, sigKey ed25519.PrivateKey, data []byte) (tx *IotTx, err error) {
	tx = new(IotTx)
	tx.Header = header
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
	if tx == nil {
		//is returning nil better?
		return [32]byte{}
	}

	txHash := struct {
		Header byte
		TxCnt  uint32
		From   [32]byte
		To     [32]byte
		Data   []byte
	}{
		tx.Header,
		tx.TxCnt,
		tx.From,
		tx.To,
		tx.Data,
	}

	return SerializeHashContent(txHash)
}

//when we serialize the struct with binary.Write, unexported field get serialized as well, undesired
//behavior. Therefore, writing own encoder/decoder
func (tx *IotTx) Encode() (encodedTx []byte) {

	//gob.Register(&ethdb.MemDatabase{})

	// Encode
	encodeData := IotTx{
		tx.Header,
		tx.TxCnt,
		tx.From,
		tx.To,
		tx.Sig,
		tx.Data,
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
			"Data: %v\n",
		tx.Header,
		tx.TxCnt,
		tx.From[0:8],
		tx.To[0:8],
		tx.Sig[0:8],
		tx.Data,
	)
}

func (tx *IotTx) Size() uint64  {
	size := int(unsafe.Sizeof(*tx))
	size += len(tx.Data)
	return uint64(size)}
func (tx *IotTx) TxFee() uint64 { return 1 }

func (tx *IotTx) Sender() [32]byte { return [32]byte{} } //Return empty because never needed.
func (tx *IotTx) Receiver() [32]byte { return [32]byte{}}


