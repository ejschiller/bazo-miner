package miner

import (
	"github.com/bazo-blockchain/bazo-miner/protocol"
	"github.com/bazo-blockchain/bazo-miner/storage"
	"sort"
)

//The code here is needed if a new block is built. All open (not yet validated) transactions are first fetched
//from the mempool and then sorted. The sorting is important because if transactions are fetched from the mempool
//they're received in random order (because it's implemented as a map). However, if a user wants to issue more fundsTxs
//they need to be sorted according to increasing txCnt, this greatly increases throughput.

type openTxs []protocol.Transaction

func prepareBlock(block *protocol.Block) {
	//Fetch all txs from mempool (opentxs).
	opentxs := storage.ReadAllOpenTxs()

	//This copy is strange, but seems to be necessary to leverage the sort interface.
	//Shouldn't be too bad because no deep copy.
	var tmpCopy openTxs
	tmpCopy = opentxs
	sort.Sort(tmpCopy)

	//Counter for all transactions which will not be aggregated. (Stake-, config-, acctx)
	nonAggregatableTxCounter := 0
	blockSize := block.GetSize()+block.GetBloomFilterSize()

	//map where all senders from FundsTx and AggTx are added to. --> this ensures that tx with same sender are only counted once.
	storage.DifferentSenders = map[[32]byte]uint32{}
	storage.DifferentReceivers = map[[32]byte]uint32{}
	for _, tx := range opentxs {
		//Switch because with an if statement every transaction would need a getter-method for its type.
		//Therefore, switch is more code-efficient.
		switch tx.(type) {
		case *protocol.FundsTx, *protocol.AggTx:
			storage.DifferentSenders[tx.Sender()] = storage.DifferentSenders[tx.Sender()]+1
			storage.DifferentReceivers[tx.Receiver()] = storage.DifferentReceivers[tx.Receiver()]+1
		default:
			nonAggregatableTxCounter += 1
		}

		//Check if block will become to big when adding the next transaction.
		if int(blockSize)+
			(len(storage.DifferentSenders)*int(len(tx.Hash()))) +
			(int(nonAggregatableTxCounter)*int(len(tx.Hash()))) > int(activeParameters.Block_size){
			break
		}
		err := addTx(block, tx)
		if err != nil {
			//If the tx is invalid, we remove it completely, prevents starvation in the mempool.
			storage.WriteINVALIDOpenTx(tx)
			storage.DeleteOpenTx(tx)
		}
	}

	//logger.Printf("DifferentSenders:   %x", storage.DifferentSenders)
	//logger.Printf("DifferentReceivers: %x", storage.DifferentReceivers)

	// In miner\block.go --> AddFundsTx the transactions get added into storage.FundsTxBeforeAggregation.
	if len(storage.ReadFundsTxBeforeAggregation()) > 0 {
		sortFundsTxBeforeAggregation(storage.ReadFundsTxBeforeAggregation())
		splitSortedAggregatableTransactions(block)
	}

	//Set measurement values back to zero / nil.
	storage.DifferentSenders = nil
	storage.DifferentReceivers = nil
	nonAggregatableTxCounter = 0

}

//Implement the sort interface
func (f openTxs) Len() int {
	return len(f)
}

func (f openTxs) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}

func (f openTxs) Less(i, j int) bool {
	//Comparison only makes sense if both tx are fundsTxs.
	//Why can we only do that with switch, and not e.g., if tx.(type) == ..?
	switch f[i].(type) {
	case *protocol.AccTx:
		//We only want to sort a subset of all transactions, namely all fundsTxs.
		//However, to successfully do that we have to place all other txs at the beginning.
		//The order between accTxs and configTxs doesn't matter.
		return true
	case *protocol.ConfigTx:
		return true
	case *protocol.StakeTx:
		return true
	case *protocol.AggTx:
		return true
	}

	switch f[j].(type) {
	case *protocol.AccTx:
		return false
	case *protocol.ConfigTx:
		return false
	case *protocol.StakeTx:
		return false
	case *protocol.AggTx:
		return false
	}

	return f[i].(*protocol.FundsTx).TxCnt < f[j].(*protocol.FundsTx).TxCnt
}