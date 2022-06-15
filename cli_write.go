package main

import (
	"fmt"
	"log"
	"time"
	"crypto/rsa"
	crand "crypto/rand"
)

func (cli *CLI) write(data string, policy string) {
	
	now := time.Now()
    Id := fmt.Sprintf("%d", now.Unix()*1e3+int64(now.Nanosecond())/1e6)
    IdByte := []byte(Id)
    
    privateKey, err := rsa.GenerateKey(crand.Reader, 2048)
    
    dca := RsaPrivateEncrypt([]byte(data), privateKey)
    
    dtx := DataTransaction{IdByte, dca, []byte{}, []byte{}}
    dtx.Sign(myKey, nodeAddress) 
    
    publicKey := RsaPublicKeyToByte(&privateKey.PublicKey)
    secret := aaa.NewSecret()
    abeConvKey := EncryptWithABESecret(publicKey, secret, policy)
    ch, r := CHash (abeConvKey, chpk)
    
    ktx := KeyTransaction{IdByte, policy, abeConvKey, r, ch, []byte{}, []byte{}}
    ktx.Sign(myKey, nodeAddress) 

	sendDataTx(knownNodes[0], dtx)
	sendKeyTx(knownNodes[0], dtx)

	fmt.Println("Success! ID: %s", Id)
}
