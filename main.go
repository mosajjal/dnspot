package main

import (
	"fmt"

	"github.com/mosajjal/dnspot/cryptography"
	"github.com/spf13/cobra"
)

func errorHandler(err error) {
	if err != nil {
		panic(err.Error())
	}
}

func generateKeys(cmd *cobra.Command, args []string) {

	privateKey, err := cryptography.GenerateKey()
	if err != nil {
		panic(err.Error())
	}
	pubKey := privateKey.GetPublicKey()
	fmt.Println("public key:", pubKey.String())
	fmt.Println("secret key:", privateKey.String())
}
