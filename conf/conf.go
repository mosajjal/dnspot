package conf

import (
	"time"

	"github.com/mosajjal/dnspot/cryptography"
)

const (
	CompressionThreshold = 1024 * 2 // 2KB
)

var GlobalServerConfig struct {
	LogFile                  string
	OutFile                  string
	LogLevel                 uint8
	PrivateKeyBasexx         string
	PrivateKey               *cryptography.PrivateKey
	ListenAddress            string
	EnforceClientKeys        bool
	AcceptedClientKeysBasexx []string
	AcceptedClientKeys       *[]cryptography.PublicKey
	DnsSuffix                string
	Mode                     string
}

var GlobalAgentConfig struct {
	CommandTimeout        time.Duration
	LogLevel              uint8
	PrivateKeyBasexx      string
	PrivateKey            *cryptography.PrivateKey
	ServerAddress         string
	ServerPublicKeyBasexx string
	ServerPublicKey       *cryptography.PublicKey
	DnsSuffix             string
}

type Runmode uint8

const (
	RunAsAgent  Runmode = 0
	RunAsServer Runmode = 1
)

var Mode Runmode
