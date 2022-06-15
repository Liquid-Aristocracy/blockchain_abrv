package main

import (
	"fmt"
	"log"
	"time"
	"crypto/rsa"
	crand "crypto/rand"
)

func (cli *CLI) updateattr(attr string, user string, isAssign bool) {
    if nodeAddress == taaddr {
	userResult := make(map[string]bool)
	userResult[user] = isAssign
	UpdateAttr (attr, userResult)
    }
}
