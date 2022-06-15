package main

import (
	"flag"
	"fmt"
	"log"

	"os"
)

// CLI responsible for processing command line arguments
type CLI struct{}

func (cli *CLI) printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  startnode")
	fmt.Println("  write -d DATA -p POLICY")
	fmt.Println("  read -i ID")
	fmt.Println("  updateattr -a ATTR -u USER -state TRUE/FALSE")
}

func (cli *CLI) validateArgs() {
	if len(os.Args) < 2 {
		cli.printUsage()
		os.Exit(1)
	}
}

// Run parses command line arguments and processes commands
func (cli *CLI) Run() {
	cli.validateArgs()

	nodeID := os.Getenv("NODE_ID")
	if nodeID == "" {
		fmt.Printf("NODE_ID env. var is not set!")
		os.Exit(1)
	}

	startNodeCmd := flag.NewFlagSet("startnode", flag.ExitOnError)
	writeCmd := flag.NewFlagSet("write", flag.ExitOnError)
	readCmd := flag.NewFlagSet("read", flag.ExitOnError)
	updateattrCmd := flag.NewFlagSet("updateattr", flag.ExitOnError)

	writeData := writeCmd.String("d", "", "Data to write")
	writePolicy := writeCmd.String("d", "", "Policy of Data")
	readId := readCmd.String("i", "", "TxID to read")
	updateAttr := updateattrCmd.String("a", "", "Attr that is updated")
	updateUser := updateattrCmd.String("u", "", "User that is updated")
	updateIsAssign := updateattrCmd.Bool("state", false, "Is assign or not")

	switch os.Args[1] {
	case "startnode":
		err := startNodeCmd.Parse(os.Args[2:])
		if err != nil {
			log.Panic(err)
		}
	case "write":
		err := writeCmd.Parse(os.Args[2:])
		if err != nil {
			log.Panic(err)
		}
	case "read":
		err := readCmd.Parse(os.Args[2:])
		if err != nil {
			log.Panic(err)
	}
	case "updateattr":
		err := updateattrCmd.Parse(os.Args[2:])
		if err != nil {
			log.Panic(err)
	}
	default:
		cli.printUsage()
		os.Exit(1)
	}
	
	if sendCmd.Parsed() {
		if *sendFrom == "" || *sendTo == "" || *sendAmount <= 0 {
			sendCmd.Usage()
			os.Exit(1)
		}

		cli.send(*sendFrom, *sendTo, *sendAmount, nodeID, *sendMine)
	}

	if startNodeCmd.Parsed() {
		nodeID := os.Getenv("NODE_ID")
		if nodeID == "" {
			startNodeCmd.Usage()
			os.Exit(1)
		}
		cli.startNode(nodeID, *startNodeMiner)
	}
	
	if writeCmd.Parsed() {
		if writeData == "" {
			writeCmd.Usage()
			os.Exit(1)
		}
		cli.write(writeData, writePolicy)
	}
	
	if readCmd.Parsed() {
		if readId == "" {
			readCmd.Usage()
			os.Exit(1)
		}
		cli.read(readId)
	}
	
	if updateattrCmd.Parsed() {
		if updateAttr == "" || updateUser == "" {
			updateattrCmd.Usage()
			os.Exit(1)
		}
		cli.updateattr(updateAttr, updateUser, updateIsAssign)
	}
}
