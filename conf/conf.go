package conf

import "github.com/mosajjal/dnspot/cryptography"

var GlobalServerConfig struct {
	PrivateKeyB32         string
	PrivateKey            *cryptography.PrivateKey
	ListenAddress         string
	EnforceClientKeys     bool
	AcceptedClientKeysB32 []string
	AcceptedClientKeys    *[]cryptography.PublicKey
	DnsSuffix             string
}

var GlobalAgentConfig struct {
	PrivateKeyB32      string
	PrivateKey         *cryptography.PrivateKey
	ServerAddress      string
	ServerPublicKeyB32 string
	ServerPublicKey    *cryptography.PublicKey
	DnsSuffix          string
}

type Runmode uint8

const (
	RunAsAgent  Runmode = 0
	RunAsServer Runmode = 1
)

var Mode Runmode
