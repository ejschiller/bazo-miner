package storage

import (
	"github.com/bazo-blockchain/bazo-miner/protocol"
)


func UpdateBlocksToBlocksWithoutTx(block *protocol.Block) (err error){

	if BlockReadyToAggregate(block) {
		block.Aggregated = true
		logger.Printf("UPDATE: Write (%x) into emptyBlockBucket as (%x)", block.Hash[0:8], block.HashWithoutTx[0:8])
		WriteClosedBlockWithoutTx(block)
		DeleteClosedBlock(block.Hash)
		return err
	}
	return
}

func BlockReadyToAggregate(block *protocol.Block) bool {

	// If Block contains no transactions, it can be viewed as aggregated and moved to the according bucket.
	if (block.NrAggTx == 0) && (block.NrStakeTx == 0) && (block.NrFundsTx == 0) && (block.NrAccTx == 0) && (block.NrConfigTx == 0)  && (block.NrIoTTx == 0){
		return true
	}

	return false
}
