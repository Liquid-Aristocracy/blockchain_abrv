package main

import (
    "bytes"
    "crypto/x509"
    "encoding/json"
    "encoding/gob"
    "fmt"
    "io/ioutil"
    "log"
    "path"
    "time"
    
    "github.com/marcellop71/mosaic/abe"
    "github.com/mervick/aes-everywhere/go/aes256"
    "crypto"
    "crypto/rsa"
    "math/rand"
    crand "crypto/rand"
    "encoding/pem"
    "encoding/base64"
    "math/big"
)

var AuthPubOfAttr = make(map[string]*abe.AuthPub) // map attr authpub
var AuthPrvOfAttr = make(map[string]*abe.AuthPrv) // map attr authprv
var AttrList = []string{"Normal@Auth0", "Special@Auth0", "Miner@Auth0"}

type AbeAuthAsset struct {
    AbeCurve abe.Curve
    AbeOrg   *abe.Org
}

type mapkey struct {
    Attr string
    User string
}

var isUserHavingAttr = make(map[mapkey]bool)

func UserHavingAttr(attr string, user string) bool {
    key := mapkey{attr, user}    
    if containsKey(isUserHavingAttr, key) {
        return isUserHavingAttr[key]
    }
    return false
}

func HandleNewUser (user string) {
    isUserHavingAttr[mapkey{"Normal@Auth0", user}] = true
    if user == mineraddr {
        isUserHavingAttr[mapkey{"Miner@Auth0", user}] = true
        isUserHavingAttr[mapkey{"Special@Auth0", user}] = true
    }
}

type KeyChainAsset struct {
    SecretHash       string
    Secret           *abe.Ciphertext
    EncryptedConvKey []byte
}

func InitABE (TA string) *AbeAuthAsset {
    // Init ABE org
    abeSeed := "this-is-some-random-thing-for-trusted-auth-idk"
    abeCurve := abe.NewCurve()
    abeCurve.SetSeed(abeSeed).InitRng()
    abeOrg := abe.NewRandomOrg(abeCurve)
    
    for _, attr := range AttrList {
        abeAuthKeys := abe.NewRandomAuth(abeOrg)
        AuthPubOfAttr[attr] = abeAuthKeys.AuthPub
        AuthPrvOfAttr[attr] = abeAuthKeys.AuthPrv
        isUserHavingAttr[mapkey{attr, TA}] = true
    }
    
    return &AbeAuthAsset{abeCurve, abeOrg}
}

func (aaa AbeAuthAsset) NewSecret() string {
    return abe.Encode(abe.JsonObjToStr(abe.NewRandomSecret(aaa.AbeOrg).ToJsonObj()))
}

func AssignKey (user string, aaa AbeAuthAsset) []byte {
    var userKey abe.UserAttrs
    for attr := range AttrList {
        if UserHavingAttr(attr, user) {
            userKey.Add(abe.NewRandomUserkey(user, attr, AuthPrvOfAttr[attr]))
        }
    }
    if userKey == nil {
        fmt.Printf("Unseen user %s.\n", user)
    }
    return userKey.Serialize()
}

func UpdateAttr (attr string, userResult map[string]bool, aaa AbeAuthAsset) {
    for user, result := range userResult {
        isUserHavingAttr[mapkey{attr, user}] = result
    }
    abeAuthKeys := abe.NewRandomAuth(aaa.AbeOrg)
    AuthPubOfAttr[attr] = abeAuthKeys.AuthPub
    AuthPrvOfAttr[attr] = abeAuthKeys.AuthPrv
}

func SerializeABEKey (userAttrs abe.UserAttrs) []byte {
    var encoded bytes.Buffer

	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(userAttrs)
    
    if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

func DeserializeABEKey(data []byte) *abe.UserAttrs {
	var userAttrs *abe.UserAttrs

	decoder := gob.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&userAttrs)
	if err != nil {
		log.Panic(err)
	}

	return userAttrs
}

func (kca *KeyChainAsset) Serialize() []byte {
    var encoded bytes.Buffer

	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(kca)
    
    if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

func DeserializeKeyChainAsset (data []byte) KeyChainAsset {
	var kca KeyChainAsset

	decoder := gob.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&kca)
	if err != nil {
		log.Panic(err)
	}

	return kca
}

func EncryptWithABESecret (data []byte, secretJson string, policy string) []byte {
    secret := abe.NewPointOfJsonStr(secretJson)
    password := secret.GetP()
    encrypted := aes256.Encrypt(base64.StdEncoding.EncodeToString(data), password)
    
    policy = abe.RewritePolicy(policy)
    authPubs := abe.AuthPubsOfPolicy(policy)
    for attr, _ := range authPubs.AuthPub {
        authPubs.AuthPub[attr] = AuthPubOfAttr[attr]
    }
    ct := abe.Encrypt(secret, policy, authPubs)
    
    keyChainAsset := &KeyChainAsset{abe.SecretHash(secret), ct, encrypted}
    return keyChainAsset.Serialize()
}

func DecryptWithABEKey (keyOnChain []byte, abeKey []byte, policy string) []byte {
    userAttrs := DeserializeABEKey(abeKey)
    kca := DeserializeKeyChainAsset(keyOnChain)
    
    userAttrs.SelectUserAttrs(userAttrs.User, policy)
    
    secret := abe.Decrypt(kca.Secret, userAttrs)
    if kca.SecretHash != abe.SecretHash(secret) {
        fmt.Printf("*** Cannot decrypt key, need %s\n", policy)
        return nil
    } else {
        fmt.Printf("*** Policy %s satisfied, key readable\n", policy)
    }
    
    password := secret.ToJsonObj().GetP()
    decrypted := aes256.Decrypt(kca.EncryptedConvKey, password)
    
    dec, err := base64.StdEncoding.DecodeString(decrypted)
    if err != nil {
		log.Panic(err)
	}
    
    return dec
}

func IsAttrInPolicy (attr string, policy string) bool {
    policy = abe.RewritePolicy(policy)
    authpubs := abe.AuthPubsOfPolicy(policy)
    for pattr, _ := range authPubs.AuthPub {
        if attr == pattr {
            return true
        }
    }
    return false
}

func AttrOfUser (user string) []string {
    var alist []string
    for attr := range AttrList {
        if UserHavingAttr (attr, user) {
            alist = append(alist, attr)
        }
    }
    return alist
}

func UserOfAttr (attr string, userlist []string) []string {
    var ulist []string
    for user := range userlist {
        if UserHavingAttr (attr, user) {
            ulist = append(ulist, user)
        }
    }
    return ulist
}
