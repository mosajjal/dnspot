package server

import (
	"bytes"
	"crypto"
	"encoding/base32"
	"strings"
	"time"

	"github.com/kpango/glg"
	"github.com/lunixbochs/struc"

	"github.com/miekg/dns"
	"github.com/mosajjal/dnspot/c2"
	"github.com/mosajjal/dnspot/cryptography"
	"github.com/spf13/cobra"
)

var dnsSuffix string

var privateKeyGlobal crypto.PrivateKey

func errorHandler(err error) {
	if err != nil {
		panic(err.Error())
	}
}

func parseQuery(m *dns.Msg) error {
	for _, q := range m.Question {
		if strings.HasSuffix(q.Name, dnsSuffix) {
			q.Name = strings.TrimSuffix(q.Name, dnsSuffix)
			msgRaw := strings.Replace(q.Name, ".", "", -1)
			if i := len(msgRaw) % 4; i != 0 {
				msgRaw += strings.Repeat("=", 4-i)
			}
			msg, err := base32.StdEncoding.DecodeString(msgRaw)
			if err != nil {
				return err
			}
			decrypted, err := cryptography.Decrypt(privateKeyGlobal, msg)
			if err != nil {
				return err
			}
			o := c2.MessagePacket{}
			err = struc.Unpack(bytes.NewBuffer(decrypted), &o)
			if err != nil {
				return err
			}
			glg.Infof("decrypted: %#v", o)
			glg.Infof("decrypted: %#d", o.TimeStamp)
		}

	}
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
			glg.Warnf("bad request: %s", err)
		}
	}

	w.WriteMsg(m)
}

func runDns(cmd *cobra.Command) {
	listenAddress, err := cmd.Flags().GetString("listenAddress")
	errorHandler(err)
	dns.HandleFunc(".", handle53)

	// start server
	server := &dns.Server{Addr: listenAddress, Net: "udp"}
	glg.Infof("Started DNS on %s -- listening", server.Addr)
	err = server.ListenAndServe()
	errorHandler(err)
	defer server.Shutdown()
}

func RunServer(cmd *cobra.Command, args []string) {
	var err error

	privateKey, err := cmd.Flags().GetString("privateKey")
	errorHandler(err)

	privateKeyGlobal, err = cryptography.PrivateKeyFromString(privateKey)
	errorHandler(err)

	dnsSuffix, err = cmd.Flags().GetString("dnsSuffix")
	errorHandler(err)
	if !strings.HasSuffix(dnsSuffix, ".") {
		dnsSuffix = dnsSuffix + "."
	}
	if !strings.HasPrefix(dnsSuffix, ".") {
		dnsSuffix = "." + dnsSuffix
	}
	go runDns(cmd)
	timeticker := time.Tick(60 * time.Second)
	for range timeticker {
		glg.Infof("All systems are healthy")
	}

}
