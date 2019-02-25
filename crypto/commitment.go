package crypto

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"io"
	"os"
	cryptorand "crypto/rand"

)

const (
	// Note that this is the default public exponent set by Golang in rsa.go
	// See https://github.com/golang/go/blob/6269dcdc24d74379d8a609ce886149811020b2cc/src/crypto/rsa/rsa.go#L226
	COMM_PROOF_LENGTH_ED 	= 64
	COMM_KEY_LENGTH_ED      = 32

)
func ExtractSeedKeyFromFile(filename string) (privKey ed25519.PrivateKey, err error) {

	if _, err = os.Stat(filename); os.IsNotExist(err) {
		err = CreateSeedKeyFile(filename)
		if err != nil {
			return privKey, err
		}
	}

	filehandle, err := os.Open(filename)
	if err != nil {
		return privKey, errors.New(fmt.Sprintf("%v", err))
	}
	defer filehandle.Close()

	scanner := bufio.NewScanner(filehandle)

	seed := nextLine(scanner)

	if scanErr := scanner.Err(); scanErr != nil || err != nil {
		return privKey, errors.New(fmt.Sprintf("Could not read key from file: %v", err))
	}

	privKey = CreatePrivKeyFromBase64(seed)

	return privKey, VerifySeedKey(privKey)
}

func VerifySeedKey(privKey ed25519.PrivateKey) error {
	message := "Test"
	cipher, err := SignMessageWithSeedKey(privKey, message)
	if err != nil {
		return errors.New(fmt.Sprintf("Could not sign message. Failed with error: %v", err))
	}
	pubKey := getPubKeyFromPrivKey(privKey)
	valid := VerifyMessageWithSeedKey(pubKey, message, cipher)
	if !valid {
		return errors.New(fmt.Sprintf("Could not verify message. Failed with error"))
	}
	return nil
}

func getPubKeyFromPrivKey(privKey ed25519.PrivateKey) (pubKey ed25519.PublicKey) {
	publicKey := make([]byte, 32)
	copy(publicKey, privKey[32:])
	return publicKey
}

func VerifyMessageWithSeedKey(pubKey ed25519.PublicKey, msg string, fixedSig [COMM_PROOF_LENGTH_ED]byte) (valid bool) {
	return ed25519.Verify(pubKey,[]byte(msg), fixedSig[:])
}

func SignMessageWithSeedKey(privKey ed25519.PrivateKey, msg string) (fixedSig [COMM_PROOF_LENGTH_ED]byte, err error) {
	sig := ed25519.Sign(privKey, []byte(msg))
	if err != nil {
		return fixedSig, err
	}
	copy(fixedSig[:], sig[:])
	return fixedSig, nil
}

func CreatePrivKeyFromBase64(seed string) (privKey ed25519.PrivateKey) {
	seedTmp := seedFromBase64(seed)
	return ed25519.NewKeyFromSeed(seedTmp)
}

func seedFromBase64(encoded string) ([]byte) {


	byteArray, encodeErr := base64.StdEncoding.DecodeString(encoded)
	if encodeErr != nil {
		return []byte{}
	}

	return byteArray
}

func CreateSeedKeyFile(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}

	seed, err := GenerateSeedKey()
	if err != nil {
		return err
	}

	_, err = file.WriteString(stringifySeedKey(seed))
	return err
}


func GenerateSeedKey() ([]byte, error) {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(cryptorand.Reader, seed); err != nil {
		return nil, err
	}
	return seed,nil
}

func stringifySeedKey(seed []byte) string {
	return base64.StdEncoding.EncodeToString(seed)
}



func nextLine(scanner *bufio.Scanner) string {
	scanner.Scan()
	return scanner.Text()
}

func SignMessageWithED(privKey ed25519.PrivateKey, msg string) (sig []byte){
	sig = ed25519.Sign(privKey, []byte(msg))
	return sig
}

func VerifyMessageWithED(pubKey [32]byte, msg string, sig []byte) (valid bool){
	return ed25519.Verify(GetPubKeyFromAddressED(pubKey),[]byte(msg), sig)
}