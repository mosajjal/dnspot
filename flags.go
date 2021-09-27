package main

import (
	"github.com/mosajjal/dnspot/agent"
	"github.com/mosajjal/dnspot/server"
	"github.com/spf13/cobra"
)

func main() {
	// main C2 function
	var cmdServer = &cobra.Command{
		Use:   "server [arguments]",
		Short: "Start DNSpot in Server mode",
		Long: `Server Mode listens on a UDP port, and awaits DNS requests.
		based on the target message, it will attempt to respond to it`,
		Args: cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			server.RunServer(cmd, args)
		},
	}
	var enforceClientKeys bool
	cmdServer.Flags().String("privateKey", "", "Private Key used")
	cmdServer.MarkFlagRequired("privateKey")
	cmdServer.Flags().String("listenAddress", "0.0.0.0:53", "Listen Socket")
	cmdServer.Flags().BoolVarP(&enforceClientKeys, "enforceClientKeys", "", false, "Enforce client keys. Need to provide a list of accepted public keys if set to true")
	cmdServer.Flags().StringSlice("acceptedClientKeys", []string{}, "Accepted Client Keys")
	cmdServer.Flags().String("dnsSuffix", ".example.com.", "Subdomain that serves the domain, please note the dot at the beginning and the end")
	cmdServer.MarkFlagRequired("dnsSuffix")

	// the Agent (client) command
	var cmdAgent = &cobra.Command{
		Use:   "agent [arguments]",
		Short: "Start DNSpot in Agent mode",
		Long: `Agent mode attempts to send DNS packets to a specified domain
		It authenticates the response using the public key of the server,
		and based on the received data, it will potentially take actions`,
		Args: cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			agent.RunAgent(cmd, args)
		},
	}
	cmdAgent.Flags().String("privateKey", "", "Private Key used")
	cmdAgent.MarkFlagRequired("privateKey")
	cmdAgent.Flags().String("serverPublicKey", "", "Server's public Key")
	cmdAgent.MarkFlagRequired("serverPublicKey")
	cmdAgent.Flags().String("dnsSuffix", ".example.com.", "Subdomain that serves the domain, please note the dot at the beginning and the end")
	cmdAgent.MarkFlagRequired("dnsSuffix")
	cmdAgent.Flags().String("serverAddress", "", "DNS Server to use. You can specify custom port here. Leave blank to use system's DNS server")
	cmdAgent.MarkFlagRequired("serverAddress")

	// helper function to spit out keys
	var cmdGenerateKey = &cobra.Command{
		Use:   "generate [arguments]",
		Short: "generate a pair of keys randomly",
		Long:  `The keys can be used for client and/or server side.`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			generateKeys(cmd, args)
		},
	}

	var rootCmd = &cobra.Command{Use: "dnspot"}
	rootCmd.AddCommand(cmdServer, cmdAgent, cmdGenerateKey)
	rootCmd.Execute()
}
