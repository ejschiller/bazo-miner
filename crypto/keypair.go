package crypto

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"log"
	"os"
	"strings"
)

func ExtractEDPublicKeyFromFile(filename string) (pubKey ed25519.PublicKey, err error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		err = CreateEDKeyFile(filename)
		if err != nil {
			return nil, err
		}
	}

	filehandle, err := os.Open(filename)
	if err != nil {
		return pubKey, errors.New(fmt.Sprintf("%v", err))
	}
	defer filehandle.Close()

	reader := bufio.NewReader(filehandle)

	return readEDPublicKey(reader)
}

func ExtractEDPrivKeyFromFile(filename string) (privKey ed25519.PrivateKey, err error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		err = CreateEDKeyFile(filename)
		if err != nil {
			return nil, err
		}
	}

	filehandle, err := os.Open(filename)
	if err != nil {
		return privKey, errors.New(fmt.Sprintf("%v", err))
	}
	defer filehandle.Close()

	reader := bufio.NewReader(filehandle)

	return readEDPrivateKey(reader)
}

func readEDPublicKey(reader *bufio.Reader) (pubKey ed25519.PublicKey, err error) {
	//Public Key
	pub1, err := reader.ReadString('\n')

	if err != nil {
		return pubKey, errors.New(fmt.Sprintf("Could not read key from file: %v", err))
	}
	//pubKeyFile,err := GetPubKeyFromStringED(strings.Split(pub1, "\n")[0])
	//fmt.Println("<PubKey from File> ",pubKeyFile)
	return GetPubKeyFromStringED(strings.Split(pub1, "\n")[0])
}

func readEDPrivateKey(reader *bufio.Reader) (privKey ed25519.PrivateKey, err error) {
	//Public Key

	pub, err := reader.ReadString('\n')
	priv, err := reader.ReadString('\n')


	if err != nil {
		return privKey, errors.New(fmt.Sprintf("Could not read key from file: %v", err))
	}
	//privKeyFile,err := GetPrivKeyFromStringED(pub,priv)
	//fmt.Println("<PrivKey from File> ",privKeyFile)
	return GetPrivKeyFromStringED(strings.Split(pub, "\n")[0],strings.Split(priv, "\n")[0])
}

func VerifyEDKey(privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) error {
	//Make sure the key being used is a valid one, that can sign and verify hashes/transactions
	hashed := []byte("testing")
	s := ed25519.Sign(privKey, hashed)
	if s == nil {
		return errors.New("the ed25519 key you provided is invalid and cannot sign hashes")
	}

	if !ed25519.Verify(pubKey,hashed, s) {
		return errors.New("the ecdsa key you provided is invalid and cannot verify hashes")
	}
	return nil
}

func ReadFile(filename string) (lines []string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return lines
}


func GetAddressFromPubKeyED(pubKey ed25519.PublicKey) (address [32]byte){
	for index := range pubKey {
		address[index] = pubKey[index]
	}
	return address
}

func GetPubKeyFromAddressED(address [32]byte)(pubKey ed25519.PublicKey){
	pubKey = address[:]
	return pubKey
}


func GetPubKeyFromStringED(pub1 string) (pubKey ed25519.PublicKey, err error) {
	pub, err := hex.DecodeString(pub1);

	return ed25519.PublicKey(pub), nil
}

func GetPrivKeyFromStringED(publicKey string, privateKey string) (privKey ed25519.PrivateKey, err error) {
	priv1, err := hex.DecodeString(privateKey);
	priv2, err := hex.DecodeString(publicKey);

	return ed25519.PrivateKey(append(priv1,priv2...)), nil
}

func CreateEDKeyFile(filename string) (err error) {
	pubKey, privKey, err :=ed25519.GenerateKey(rand.Reader)
	//fmt.Println("PUBKEY: ",len(pubKey),pubKey)
	//fmt.Println("PRIVKEY:",len(privKey), privKey)
	//Write the public key to the given textfile
	if _, err = os.Stat(filename); !os.IsNotExist(err) {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}

	//var pubKey [64]byte
	_, err1 := file.WriteString(hex.EncodeToString(pubKey)+ "\n")
	_, err2 := file.WriteString(hex.EncodeToString(privKey[0:32])+ "\n")
	_, err3 := file.WriteString(hex.EncodeToString(privKey[32:64])+ "\n")


	if err1 != nil || err2 != nil || err3 != nil {
		return errors.New("failed to write key to file")
	}

	return nil
}
