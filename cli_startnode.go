package main

import (
	"fmt"
	"log"
)

func (cli *CLI) startNode(nodeID) {
	fmt.Printf("Starting node %s\n", nodeID)

	StartServer(nodeID, minerAddress)
}
