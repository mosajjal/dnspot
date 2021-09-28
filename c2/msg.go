package c2

import (
	"bytes"
	"time"

	"github.com/lunixbochs/struc"
)

type ServiceList uint

const (
	ServiceNone              ServiceList = 0
	ServiceAdb               ServiceList = 1
	ServiceCopy              ServiceList = 2
	ServiceCounterstrike     ServiceList = 3
	ServiceCwmp              ServiceList = 4
	ServiceDns               ServiceList = 5
	ServiceDnsProxy          ServiceList = 6
	ServiceEcho              ServiceList = 7
	ServiceElasticsearch     ServiceList = 8
	ServiceEos               ServiceList = 9
	ServiceEthereum          ServiceList = 10
	ServiceFtp               ServiceList = 11
	ServiceHttp              ServiceList = 12
	ServiceHttps             ServiceList = 13
	ServiceHttpProxy         ServiceList = 14
	ServiceIpp               ServiceList = 15
	ServiceLdap              ServiceList = 16
	ServiceMemcached         ServiceList = 17
	ServiceRedis             ServiceList = 18
	ServiceSmtp              ServiceList = 19
	ServiceSshAuthentication ServiceList = 20
	ServiceSshJail           ServiceList = 21
	ServiceSshSimulator      ServiceList = 22
	ServiceSshProxy          ServiceList = 23
	ServiceTelnet            ServiceList = 24
	ServiceVnc               ServiceList = 25
	ServiceTftp              ServiceList = 26
)

type Message uint

// Message codes
const (
	MessageHealthcheck Message = 0
	MessageSyncTime    Message = 1
	MessageSetService  Message = 2
	MessageLogService  Message = 3
)

type TimeStamp struct {
}

// healthCheck gets sent by the agent every n seconds
// show that the host is alive and it can recive further instructions
// as part of this healthCheck's response from the server
// note that we'll use the agent's public key as their ID, so no need to put it again here
// also we only have 69 bytes for the entire message if the subdomain is xx.xxx.xx (9 chars)
type MessagePacket struct {
	TimeStamp      uint32      `struc:"uint32,little"`
	MessageType    Message     `struc:"uint8,little"`
	EnabledService ServiceList `struc:"uint8,little"`
	IsMultiPart    bool        `struc:"bool,little"`
	PartID         uint16      `struc:"uint16,little"`
	ParentPartID   uint16      `struc:"uint16,little"`
	Payload        [58]byte    `struc:"[58]byte,little"`
}

func main() {
	var buf bytes.Buffer
	msg := MessagePacket{
		TimeStamp:      uint32(time.Now().Unix()),
		MessageType:    MessageHealthcheck,
		EnabledService: ServiceNone,
		IsMultiPart:    false,
		PartID:         0,
		ParentPartID:   0,
	}
	struc.Pack(&buf, msg)
}
