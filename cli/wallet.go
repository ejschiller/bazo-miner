package cli

import (
	"fmt"
	"github.com/bazo-blockchain/bazo-miner/crypto"
	"github.com/urfave/cli"
)

func GetGenerateWalletCommand() cli.Command {
	return cli.Command {
		Name:	"generate-wallet",
		Usage:	"generate a new pair of wallet keys",
		Action:	func(c *cli.Context) error {
			filename := c.String("file")
			privKey, err := crypto.ExtractEDPrivKeyFromFile(filename)

			fmt.Printf("Wallet generated successfully.\n")
			fmt.Printf("PubKey: %x\n", privKey[32:])
			fmt.Printf("PrivKey: %x\n", privKey)

			return err
		},
		Flags:	[]cli.Flag {
			cli.StringFlag {
				Name: 	"file",
				Usage: 	"the new key's `FILE` name",
			},
		},
	}
}
