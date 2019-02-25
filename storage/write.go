package storage

import (
	"github.com/bazo-blockchain/bazo-miner/protocol"
	"github.com/boltdb/bolt"
)

func WriteOpenBlock(block *protocol.Block) (err error) {

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("openblocks"))
		err := b.Put(block.Hash[:], block.Encode())
		return err
	})

	return err
}

func WriteClosedBlock(block *protocol.Block) (err error) {

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("closedblocks"))
		err := b.Put(block.Hash[:], block.Encode())
		return err
	})

	return err
}

func WriteClosedBlockWithoutTx(block *protocol.Block) (err error) {

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("closedblockswithouttx"))
		err := b.Put(block.HashWithoutTx[:], block.Encode())
		return err
	})

	return err
}

func WriteLastClosedBlock(block *protocol.Block) (err error) {

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("lastclosedblock"))
		err := b.Put(block.Hash[:], block.Encode())
		return err
	})

	return err
}

//Changing the "tx" shortcut here and using "transaction" to distinguish between bolt's transactions
func WriteOpenTx(transaction protocol.Transaction) {
	openTxMutex.Lock()
	defer openTxMutex.Unlock()
	txMemPool[transaction.Hash()] = transaction
}

func WriteFundsTxBeforeAggregation(transaction *protocol.FundsTx) {
	openFundsTxBeforeAggregationMutex.Lock()
	defer openFundsTxBeforeAggregationMutex.Unlock()
	FundsTxBeforeAggregation = append(FundsTxBeforeAggregation, transaction)
}

func WriteBootstrapTxReceived(transaction protocol.Transaction) {

	bootstrapReceivedMemPool[transaction.Hash()] = transaction
}

func WriteINVALIDOpenTx(transaction protocol.Transaction) {

	txINVALIDMemPool[transaction.Hash()] = transaction
}
func WriteToReceivedStash(block *protocol.Block) {

	//Only write it to stash if it is not in there already.
	if !blockAlreadyInStash(receivedBlockStash, block.Hash) {
		receivedBlockStash = append(receivedBlockStash, block)

		//When length of stash is > 50 --> Remove first added Block
		if len(receivedBlockStash) > 50 {
			receivedBlockStash = append(receivedBlockStash[:0], receivedBlockStash[1:]...)
		}
	}
}

func blockAlreadyInStash(slice []*protocol.Block, newBlockHash [32]byte) bool {
	for _, blockInStash := range slice {
		if blockInStash.Hash == newBlockHash {
			return true
		}
	}
	return false
}

func WriteClosedTx(transaction protocol.Transaction) (err error) {

	var bucket string
	switch transaction.(type) {
	case *protocol.FundsTx:
		bucket = "closedfunds"
	case *protocol.AccTx:
		bucket = "closedaccs"
	case *protocol.ConfigTx:
		bucket = "closedconfigs"
	case *protocol.StakeTx:
		bucket = "closedstakes"
	case *protocol.AggTx:
		bucket = "closedaggregations"
	}

	hash := transaction.Hash()
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		err := b.Put(hash[:], transaction.Encode())
		return err
	})
	nrClosedTransactions = nrClosedTransactions + 1
	totalTransactionSize = totalTransactionSize + float32(transaction.Size())
	averageTxSize = totalTransactionSize/nrClosedTransactions
	return err
}

func WriteAccount(account *protocol.Account) {
	State[account.Address] = account
}