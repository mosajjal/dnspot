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

	"github.com/mosajjal/dnspot/cryptography"
	"github.com/mosajjal/dnspot/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
	server := server.Server{}

	var io cmdIO
	io.in = make(chan string, 1)
	io.out = make(chan string, 1)
	go io.Handler()

	var cmdServer = &cobra.Command{
		Use:   "server [arguments]",
		Short: "Start DNSpot in Server mode",
		Long: `Server Mode listens on a UDP port, and awaits DNS requests.
		based on the target message, it will attempt to respond to it`,
		Args: cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			// setup logger level and output
			if logLevel, err := cmd.Flags().GetUint8("logLevel"); err == nil {
				zerolog.SetGlobalLevel(zerolog.Level(5 - logLevel))
			}
			if logFile, err := cmd.Flags().GetString("logFile"); logFile != "" && err == nil {
				f, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o0640)
				if err != nil {
					log.Fatal().Msgf("error opening file: %v", err)
				}
				io.logger = zerolog.New(f).With().Timestamp().Logger()
			} else {
				io.logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
			}
			server.RunServer(io)
		},
	}
	cmdServer.Flags().String("logFile", "", "Log to file. stderr is used when not provided. Optional")
	cmdServer.Flags().String("outFile", "", "Output File to record only the commands and their responses")
	cmdServer.Flags().Uint8("logLevel", 1, "Log level. Panic:0, Fatal:1, Error:2, Warn:3, Info:4, Debug:5, Trace:6")

	cmdServer.Flags().StringVarP(&server.PrivateKeyBase36, "privateKey", "", "", "Private Key used")
	_ = cmdServer.MarkFlagRequired("privateKey")
	cmdServer.Flags().StringVarP(&server.ListenAddress, "listenAddress", "", "0.0.0.0:53", "Listen Socket")
	cmdServer.Flags().BoolVarP(&server.EnforceClientKeys, "enforceClientKeys", "", false, "Enforce client keys. Need to provide a list of accepted public keys if set to true")
	cmdServer.Flags().StringSliceVarP(&server.AcceptedClientKeysBase36, "acceptedClientKeys", "", []string{}, "Accepted Client Keys")
	cmdServer.Flags().StringVarP(&server.DNSSuffix, "dnsSuffix", "", ".example.com.", "Subdomain that serves the domain, please note the dot at the beginning and the end")
	_ = cmdServer.MarkFlagRequired("dnsSuffix")
	cmdServer.Flags().StringVarP(&server.Mode, "mode", "", "exec", "Run mode. choices: exec, chat")

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

	// var rootCmd = &cobra.Command{Use: "dnspot"}
	// rootCmd.AddCommand(cmdServer, cmdGenerateKey)
	// _ = rootCmd.Execute()

	cmdServer.AddCommand(cmdGenerateKey)
	if err := cmdServer.Execute(); err != nil {
		os.Exit(1)
	} else {
		// Exit if help was called
		if cmdServer.Flags().Changed("help") {
			os.Exit(0)
		}
	}

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
