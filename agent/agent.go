package agent

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"strings"

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

	msg := "hello lets take ssa look atchars22hello lets lets take ssa look atcha"
	// msg := "hello"
	encrypted, err := cryptography.Encrypt(public, private, []byte(msg))
	if err != nil {
		panic(err.Error())
	}

	s := base32.StdEncoding.EncodeToString(encrypted)
	glg.Infof("encrypted %s %d\n", s, len(encrypted))

	Q := insertNth(s, 63) + dnsSuffix
	if len(Q) > 255 {
		panic("too long")
	}
	q := dns.Question{Name: Q, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	fmt.Printf("%v", q)
	performExternalQuery(q, serverAddress)
}
