package server

import (
	"sort"
	"strings"
	"time"

	"github.com/kpango/glg"

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

type DnsHandler struct {
	packetBuffersWithSignature map[int][]c2.MessagePacketWithSignature
}

func checkMessageIntegrity(packets []c2.MessagePacketWithSignature) []c2.MessagePacketWithSignature {
	//sort, uniq and remove duplicates. then check if the message is complete

	//sort
	sort.Slice(packets, func(i, j int) bool {
		return packets[i].Msg.PartID < packets[j].Msg.PartID
	})

	// unique
	for i := 0; i < len(packets)-1; i++ {
		if packets[i].Msg.PartID == packets[i+1].Msg.PartID {
			packets = append(packets[:i], packets[i+1:]...)
			i--
		}
	}
	// check if the message is complete
	if len(packets) == int(packets[len(packets)-1].Msg.PartID)+1 {
		return packets
	}
	return nil
}

// clientList {

// }

// MessageHealthcheck       Message = 0
// MessageSyncTime          Message = 1
// MessageExecuteCommand    Message = 2
// MessageTransferFile      Message = 3
// MessageSetHealthInterval Message = 4

// log received healthcheck
func MessageHealthcheckHandler(Packet c2.MessagePacketWithSignature) (*dns.Msg, error) {
	glg.Infof("Healthcheck, coming from %s\n", Packet.Signature.String())
	//todo: register new clients in client list
	//todo: check pending tasks for this client
	//todo: prepare a response to reply with
	return nil, nil
}
func MessageSyncTimeHandler(payload []byte, firstPacket c2.MessagePacketWithSignature) error {
	// msg := c2.MessagePacket{
	// 	TimeStamp:   uint32(time.Now().Unix()),
	// 	MessageType: c2.MessageHealthcheck,
	// }
	// // going to send this as ISO formatted string time.Now().UTC().Format("2006-01-02T15:04:05-0700")
	// toSendPayload := []byte(time.Now().UTC().Format("2006-01-02T15:04:05-0700"))
	// c2.SendPartitionedPayload(msg, toSendPayload, handler.dnsSuffix, serverAddress, private, public)
	return nil
}

// not implemented in server side for now, so no action
func MessageTransferFileHandler(payload []byte, firstPacket c2.MessagePacketWithSignature) error {
	return nil
}
func MessageSetHealthIntervalHandler(payload []byte, firstPacket c2.MessagePacketWithSignature) error {
	return nil
}

func executeFunction(packets []c2.MessagePacketWithSignature) error {
	fullPayload := make([]byte, 0)
	packets = checkMessageIntegrity(packets)
	for _, packet := range packets {
		packetPayload := packet.Msg.Payload[:]
		fullPayload = append(fullPayload, packetPayload...)
	}
	glg.Warnf("%s, coming from %s\n", fullPayload, packets[0].Signature.String())
	// todo: clean the memory for this parentpartID
	return nil
}

func cleanupBuffer(hanlder DnsHandler, timeout time.Duration) error {
	return nil
}

func (handler *DnsHandler) parseQuery(m *dns.Msg) (*dns.Msg, error) {
	outs, err := c2.DecryptIncomingPacket(m, conf.GlobalServerConfig.DnsSuffix, conf.GlobalServerConfig.PrivateKey, nil)
	if err != nil {
		glg.Warnf("Error in Decrypting incoming packet", err)
	}
	for _, o := range outs {
		switch msgType := o.Msg.MessageType; msgType {
		case c2.MessageHealthcheck:
			return MessageHealthcheckHandler(o)
		case c2.MessageExecuteCommand:
			return nil, nil // command execution from client to server is not implemented
		case c2.MessageClientGetFile:
			return nil, nil // todo
		case c2.MessageClientSendFile:
			return nil, nil // todo
		case c2.MessageSetHealthInterval:
			return nil, nil // todo
		case c2.MessageSyncTime:
			return nil, nil // todo
		}

		// if ParentPartID = 0 -> single packet
		// if ParentPartID != 0 -> incoming packets in the order of their PartID
		// if IsLastPart == true -> last packet
		// successful request incoming, need to see which packet are we dealing with
		if o.Msg.ParentPartID != 0 { // multi part
			//fist and middle packets
			handler.packetBuffersWithSignature[int(o.Msg.ParentPartID)] = append(handler.packetBuffersWithSignature[int(o.Msg.ParentPartID)], o)
			if o.Msg.IsLastPart {
				executeFunction(handler.packetBuffersWithSignature[int(o.Msg.ParentPartID)])
			}
			//todo: prepare response
			return nil, nil
		} else { // single packet
			executeFunction([]c2.MessagePacketWithSignature{o})
			// todo: prepare response
		}

	}

	// }
	//todo: prepare response
	return nil, nil
}

func (handler *DnsHandler) handle53(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		_, err := handler.parseQuery(m)
		if err != nil {
			glg.Warnf("bad request: %s", err)
		}
	}

	w.WriteMsg(m)
}

func runDns(cmd *cobra.Command) {

	handler := &DnsHandler{
		packetBuffersWithSignature: make(map[int][]c2.MessagePacketWithSignature),
	}
	dns.HandleFunc(".", handler.handle53)

	// start server
	server := &dns.Server{Addr: conf.GlobalServerConfig.ListenAddress, Net: "udp"}
	glg.Infof("Started DNS on %s -- listening", server.Addr)
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
	timeticker := time.Tick(60 * time.Second)
	for range timeticker {
		// cleanupBuffer(*handler, 60*time.Second) //TODO: make this work
		glg.Infof("All systems are healthy")
	}
}
