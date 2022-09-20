package main

import (
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
	"github.com/mosajjal/dnspot/agent"
	"github.com/mosajjal/dnspot/conf"
	"github.com/mosajjal/dnspot/cryptography"
	"github.com/mosajjal/dnspot/server"
	"github.com/spf13/cobra"
)

func generateKeys(cmd *cobra.Command, args []string) {

	privateKey, err := cryptography.GenerateKey()
	if err != nil {

		panic(err.Error())
	}
	pubKey := privateKey.GetPublicKey()
	fmt.Println("public  key:", pubKey.String())
	fmt.Println("private key:", privateKey.String())
}

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

	cmdServer.Flags().StringVarP(&conf.GlobalServerConfig.LogFile, "logFile", "", "", "Log output file. Optional")
	cmdServer.Flags().StringVarP(&conf.GlobalServerConfig.OutFile, "outFile", "", "", "Output File to record only the commands and their responses")
	cmdServer.Flags().Uint8VarP(&conf.GlobalServerConfig.LogLevel, "logLevel", "", 1, "Log level. Panic:0, Fatal:1, Error:2, Warn:3, Info:4, Debug:5, Trace:6")
	cmdServer.Flags().StringVarP(&conf.GlobalServerConfig.PrivateKeyBasexx, "privateKey", "", "", "Private Key used")
	_ = cmdServer.MarkFlagRequired("privateKey")
	cmdServer.Flags().StringVarP(&conf.GlobalServerConfig.ListenAddress, "listenAddress", "", "0.0.0.0:53", "Listen Socket")
	cmdServer.Flags().BoolVarP(&conf.GlobalServerConfig.EnforceClientKeys, "enforceClientKeys", "", false, "Enforce client keys. Need to provide a list of accepted public keys if set to true")
	cmdServer.Flags().StringSliceVarP(&conf.GlobalServerConfig.AcceptedClientKeysBasexx, "acceptedClientKeys", "", []string{}, "Accepted Client Keys")
	cmdServer.Flags().StringVarP(&conf.GlobalServerConfig.DnsSuffix, "dnsSuffix", "", ".example.com.", "Subdomain that serves the domain, please note the dot at the beginning and the end")
	_ = cmdServer.MarkFlagRequired("dnsSuffix")

	// the Agent (client) command
	var cmdAgent = &cobra.Command{
		Use:   "agent [arguments]",
		Short: "Start DNSpot in Agent mode",
		Long: `Agent mode attempts to send DNS packets to a specified domain
		It authenticates the response using the public key of the server,
		and based on the received data, it will potentially take actions`,
		Args: cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			log.Fatalln(agent.RunAgent(cmd, args))
		},
	}

	cmdAgent.Flags().DurationVarP(&conf.GlobalAgentConfig.CommandTimeout, "timeout", "", 2*time.Second, "Timeout for DNS requests")
	cmdAgent.Flags().Uint8VarP(&conf.GlobalAgentConfig.LogLevel, "loglevel", "", 1, "log level. Panic:0, Fatal:1, Error:2, Warn:3, Info:4, Debug:5, Trace:6")
	cmdAgent.Flags().StringVarP(&conf.GlobalAgentConfig.PrivateKeyBasexx, "privateKey", "", "", "Private Key used. Generates one on the fly if empty")
	// cmdAgent.MarkFlagRequired("privateKey")
	cmdAgent.Flags().StringVarP(&conf.GlobalAgentConfig.ServerPublicKeyBasexx, "serverPublicKey", "", "", "Server's public Key")
	_ = cmdAgent.MarkFlagRequired("serverPublicKey")
	cmdAgent.Flags().StringVarP(&conf.GlobalAgentConfig.DnsSuffix, "dnsSuffix", "", ".example.com.", "Subdomain that serves the domain, please note the dot at the beginning and the end")
	_ = cmdAgent.MarkFlagRequired("dnsSuffix")
	cmdAgent.Flags().StringVarP(&conf.GlobalAgentConfig.ServerAddress, "serverAddress", "", "", "DNS Server to use. You can specify custom port here. Leave blank to use system's DNS server")
	if conf.GlobalAgentConfig.ServerAddress == "" {
		systemDNS, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
		conf.GlobalAgentConfig.ServerAddress = systemDNS.Servers[0] + ":53"
	}

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
	log.Fatalln(rootCmd.Execute())
}
