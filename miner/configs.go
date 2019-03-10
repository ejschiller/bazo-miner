package miner

const (
	//How many blocks can we verify dynamically (e.g. proper time check) until we are too far behind
	//that this dynamic check is not possible anymore?!
	DELAYED_BLOCKS = 10

	TXFETCH_TIMEOUT    = 5  //Sec
	BLOCKFETCH_TIMEOUT = 40 //Sec

	//Some prominent programming languages (e.g., Java) have not unsigned integer types
	//Neglecting MSB simplifies compatibility
	MAX_MONEY = 9223372036854775807 //(2^63)-1

	//Default Block params
	BLOCKHASH_SIZE       	= 32      //Byte
	FEE_MINIMUM          	= 1       //Coins
	BLOCK_SIZE           	= 20000 //Byte
	DIFF_INTERVAL        	= 15      //Blocks
	BLOCK_INTERVAL       	= 15      //Sec
	BLOCK_REWARD         	= 0       //Coins
	STAKING_MINIMUM      	= 1000    //Coins
	WAITING_MINIMUM      	= 0       //Blocks
	ACCEPTED_TIME_DIFF   	= 60      //Sec
	SLASHING_WINDOW_SIZE 	= 100     //Blocks
	SLASH_REWARD         	= 2       //Coins
	NUM_INCL_PREV_PROOFS 	= 5       //Number of previous proofs included in the PoS condition
	NO_AGGREGATION_LENGTH	= 3		  //Number of blocks after the newest block which are not aggregated.
)
