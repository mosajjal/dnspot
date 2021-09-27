package server

import (
	"crypto"
	"encoding/base32"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
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

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		if strings.HasSuffix(q.Name, dnsSuffix) {
			q.Name = strings.TrimSuffix(q.Name, dnsSuffix)
			msgRaw := strings.Replace(q.Name, ".", "", -1)
			msg, err := base32.StdEncoding.DecodeString(msgRaw)
			if err != nil {
				fmt.Println("error")
			}
			println("here")
			decrypted, err := cryptography.Decrypt(privateKeyGlobal, msg)
			if err != nil {

				panic(err.Error())
			}
			fmt.Printf("decrypted %x %s", decrypted, string(decrypted))
		}

	}

}

func handle53(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	w.WriteMsg(m)
}

func runDns(cmd *cobra.Command) {
	listenAddress, err := cmd.Flags().GetString("listenAddress")
	errorHandler(err)
	dns.HandleFunc(".", handle53)

	// start server
	server := &dns.Server{Addr: listenAddress, Net: "udp"}
	log.Printf("Started DNS on %s -- listening", server.Addr)
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

	go runDns(cmd)
	timeticker := time.Tick(60 * time.Second)
	for {
		select {
		case <-timeticker:
			continue
		}
	}

}
