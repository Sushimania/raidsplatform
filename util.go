package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/btcsuite/btcutil"
	"github.com/dgrijalva/jwt-go"
	"log"
	"time"
)

var (
	secret = JWT_SECURE_KEY
)

// --------------------------------- auth token ---------------------------------
type ClientToken struct {
	EosAccountName string	`json:"eosAccountName"`
	MachineId string	`json:"machineId"`
	Expire int	`json:"expire"`
	jwt.StandardClaims
}

func CreateToken(eosAccountName string, machineId string) string {
	expire := int(time.Now().Unix()) + 84600

	// Embed User information to `token`
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), &ClientToken{
		EosAccountName: eosAccountName,
		MachineId: machineId,
		Expire: expire,
	})
	// token -> string. Only server knows this secret (foobar).
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		log.Fatalln(err)
	}
	return tokenString
}

func ValidateToken(tokenString string) (bool, string) {
	clientToken := ClientToken{}
	token, err := jwt.ParseWithClaims(tokenString, &clientToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	log.Println(token.Valid, clientToken, err)

	if clientToken.Expire < int(time.Now().Unix()) {
		return false, clientToken.EosAccountName
	}

	return token.Valid, clientToken.EosAccountName
}

// --------------------------------- HMAC ---------------------------------
func checkMAC(message string, messageMAC string, secret string) bool {
	equalFlag := false
	sha := hashMAC(message, secret)
	if messageMAC == sha {
		equalFlag = true
	}
	return equalFlag
}

func hashMAC(message string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	sha := hex.EncodeToString(h.Sum(nil))
	return sha
}

func ImportWIF(wifStr string) (*btcutil.WIF, error) {
	wif, err := btcutil.DecodeWIF(wifStr)
	if err != nil {
		return nil, err
	}
	return wif, nil
}