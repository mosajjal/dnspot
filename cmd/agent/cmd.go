// package cmd provides a command-line interface for dnspot
// this allows the application logic and the user interaction
// to be decoupled, which provides a consice API for further
// development of dnspot
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mosajjal/dnspot/agent"
	"github.com/mosajjal/dnspot/cryptography"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

type cmdIO struct {
	in     chan string
	out    chan string
	logger zerolog.Logger
}

func (io cmdIO) Logger(level uint8, format string, args ...interface{}) {
	io.logger.WithLevel(zerolog.Level(level)).Msgf(format, args...)
}
func (io cmdIO) GetInputFeed() chan string {
	return io.in
}
func (io cmdIO) GetOutputFeed() chan string {
	return io.out
}

func (io cmdIO) Handler() {

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Press Ctrl+D to exit")
	go func() {
		for {
			fmt.Print("-> ")
			text, err := reader.ReadString('\n')
			if err != nil {
				os.Exit(0)
			}
			// convert CRLF to LF
			text = strings.Replace(text, "\n", "", -1)
			if len(text) > 0 {
				io.in <- text
			}
		}
	}()

	for out := range io.out {
		fmt.Print(out)
		fmt.Print("\n-> ")

	}
}

func main() {

	var io cmdIO
	io.in = make(chan string, 1)
	io.out = make(chan string, 1)
	go io.Handler()

	var cmdAgent = &cobra.Command{
		Use:   "agent [arguments]",
		Short: "Start DNSpot in Agent mode",
		Long: `Agent mode attempts to send DNS packets to a specified domain
		It authenticates the response using the public key of the server,
		and based on the received data, it will potentially take actions`,
		Args: cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if logLevel, err := cmd.Flags().GetUint8("logLevel"); err == nil {
				zerolog.SetGlobalLevel(zerolog.Level(5 - logLevel))
			}
			io.logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
			agent.RunAgent(io)
		},
	}

	cmdAgent.Flags().Uint8("logLevel", 1, "log level. Panic:0, Fatal:1, Error:2, Warn:3, Info:4, Debug:5, Trace:6")

	cmdAgent.Flags().DurationVarP(&agent.Config.CommandTimeout, "timeout", "", 2*time.Second, "Timeout for command execution")
	cmdAgent.Flags().StringVarP(&agent.Config.PrivateKeyBase36, "privateKey", "", "", "Private Key used. Generates one on the fly if empty")
	cmdAgent.Flags().StringVarP(&agent.Config.ServerPublicKeyBase36, "serverPublicKey", "", "", "Server's public Key")
	_ = cmdAgent.MarkFlagRequired("serverPublicKey")
	cmdAgent.Flags().StringVarP(&agent.Config.DnsSuffix, "dnsSuffix", "", ".example.com.", "Subdomain that serves the domain, please note the dot at the beginning and the end")
	_ = cmdAgent.MarkFlagRequired("dnsSuffix")
	cmdAgent.Flags().StringVarP(&agent.Config.ServerAddress, "serverAddress", "", "", "DNS Server to use. You can specify custom port here. Leave blank to use system's DNS server")

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
	rootCmd.AddCommand(cmdAgent, cmdGenerateKey)
	_ = rootCmd.Execute()

	// handle interrupts
	signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-signalChannel
		switch sig {
		case os.Interrupt:
			os.Exit(0)
		case syscall.SIGTERM:
			os.Exit(0)
		}
	}()

	// block
	select {}

}
