// package cmd provides a command-line interface for dnspot
// this allows the application logic and the user interaction
// to be decoupled, which provides a consice API for further
// development of dnspot
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mosajjal/dnspot/agent"
	"github.com/mosajjal/dnspot/cryptography"
	"github.com/mosajjal/dnspot/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

type CmdIO struct {
	in     *chan string
	out    *chan string
	logger zerolog.Logger
}

func (io CmdIO) Logger(level uint8, format string, args ...interface{}) {
	log.WithLevel(zerolog.Level(level)).Msgf(format, args...)
}
func (io CmdIO) GetInputFeed() *chan string {
	return io.in
}
func (io CmdIO) GetOutputFeed() *chan string {
	return io.out
}

func (io CmdIO) Handler() {

	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("-> ")
			text, _ := reader.ReadString('\n')
			// convert CRLF to LF
			text = strings.Replace(text, "\n", "", -1)
			if len(text) > 0 {
				*io.in <- text
			}
		}
	}()

	for out := range *io.out {
		fmt.Println(out)
	}
}

func main() {

	var io CmdIO
	io.in = new(chan string)
	io.out = new(chan string)
	io.logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
	go io.Handler()

	var cmdServer = &cobra.Command{
		Use:   "server [arguments]",
		Short: "Start DNSpot in Server mode",
		Long: `Server Mode listens on a UDP port, and awaits DNS requests.
		based on the target message, it will attempt to respond to it`,
		Args: cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			server.RunServer()
		},
	}
	cmdServer.Flags().StringVarP(&server.Config.LogFile, "logFile", "", "", "Log output file. Optional")
	cmdServer.Flags().StringVarP(&server.Config.OutFile, "outFile", "", "", "Output File to record only the commands and their responses")
	cmdServer.Flags().Uint8VarP(&server.Config.LogLevel, "logLevel", "", 1, "Log level. Panic:0, Fatal:1, Error:2, Warn:3, Info:4, Debug:5, Trace:6")
	cmdServer.Flags().StringVarP(&server.Config.PrivateKeyBase36, "privateKey", "", "", "Private Key used")
	_ = cmdServer.MarkFlagRequired("privateKey")
	cmdServer.Flags().StringVarP(&server.Config.ListenAddress, "listenAddress", "", "0.0.0.0:53", "Listen Socket")
	cmdServer.Flags().BoolVarP(&server.Config.EnforceClientKeys, "enforceClientKeys", "", false, "Enforce client keys. Need to provide a list of accepted public keys if set to true")
	cmdServer.Flags().StringSliceVarP(&server.Config.AcceptedClientKeysBase36, "acceptedClientKeys", "", []string{}, "Accepted Client Keys")
	cmdServer.Flags().StringVarP(&server.Config.DnsSuffix, "dnsSuffix", "", ".example.com.", "Subdomain that serves the domain, please note the dot at the beginning and the end")
	_ = cmdServer.MarkFlagRequired("dnsSuffix")
	cmdServer.Flags().StringVarP(&server.Config.Mode, "mode", "", "exec", "Run mode. choices: exec, chat")

	var cmdAgent = &cobra.Command{
		Use:   "agent [arguments]",
		Short: "Start DNSpot in Agent mode",
		Long: `Agent mode attempts to send DNS packets to a specified domain
		It authenticates the response using the public key of the server,
		and based on the received data, it will potentially take actions`,
		Args: cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			agent.RunAgent()
		},
	}

	cmdAgent.Flags().DurationVarP(&agent.Config.CommandTimeout, "timeout", "", 2*time.Second, "Timeout for DNS requests")
	cmdAgent.Flags().Uint8VarP(&agent.Config.LogLevel, "logLevel", "", 1, "log level. Panic:0, Fatal:1, Error:2, Warn:3, Info:4, Debug:5, Trace:6")
	cmdAgent.Flags().StringVarP(&agent.Config.PrivateKeyBase36, "privateKey", "", "", "Private Key used. Generates one on the fly if empty")
	// cmdAgent.MarkFlagRequired("privateKey")
	cmdAgent.Flags().StringVarP(&agent.Config.ServerPublicKeyBase36, "serverPublicKey", "", "", "Server's public Key")
	_ = cmdAgent.MarkFlagRequired("serverPublicKey")
	cmdAgent.Flags().StringVarP(&agent.Config.DnsSuffix, "dnsSuffix", "", ".example.com.", "Subdomain that serves the domain, please note the dot at the beginning and the end")
	_ = cmdAgent.MarkFlagRequired("dnsSuffix")
	cmdAgent.Flags().StringVarP(&agent.Config.ServerAddress, "serverAddress", "", "", "DNS Server to use. You can specify custom port here. Leave blank to use system's DNS server")
	if agent.Config.ServerAddress == "" {
		systemDNS, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
		if len(systemDNS.Servers) < 1 {
			log.Fatal().Msg("could not determine OS's default resolver. Please manually specify a DNS server")
		}
		agent.Config.ServerAddress = systemDNS.Servers[0] + ":53"
	}

	// helper function to spit out keys
	var cmdGenerateKey = &cobra.Command{
		Use:   "generate [arguments]",
		Short: "generate a pair of keys randomly",
		Long:  `The keys can be used for client and/or server side.`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			func() {
				pub, priv := cryptography.GenerateKeypair()
				fmt.Printf("public key: %s\nprivate key: %s\n", pub, priv)
			}()
		},
	}

	var rootCmd = &cobra.Command{Use: "dnspot"}
	rootCmd.AddCommand(cmdServer, cmdAgent, cmdGenerateKey)
	_ = rootCmd.Execute()
}
