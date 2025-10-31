package c2

import "time"

// Configuration constants for the C2 protocol
const (
	// PayloadSize is the maximum number of bytes that can be fit inside a C2 Msg object.
	// It will have the added headers before being sent on wire
	PayloadSize = int(70)

	// ChunkSize determines how much data each DNS query or response has.
	// After converting the msg of ChunkSize to base32, it shouldn't exceed ~250 bytes
	ChunkSize = uint8(90)

	// CompressionThreshold sets the minimum msg size to be compressed.
	// Anything lower than this size will be sent uncompressed
	CompressionThreshold = 1024 * 2 // 2KB

	// MaxDNSLabelLength is the maximum length of a DNS label (RFC 1035)
	MaxDNSLabelLength = 63

	// MaxDNSNameLength is the maximum length of a complete DNS name (RFC 1035)
	MaxDNSNameLength = 253

	// DNSQueryTimeout is the default timeout for DNS queries
	DNSQueryTimeout = 6 * time.Second

	// DefaultHealthCheckInterval is the default interval for health check messages
	DefaultHealthCheckInterval = 10 * time.Second

	// DefaultAgentHealthCheckInterval is the default interval for agent health checks
	DefaultAgentHealthCheckInterval = 3 * time.Second

	// AgentTimeoutDuration is how long to wait before considering an agent idle/dead
	AgentTimeoutDuration = 60 * time.Second

	// MaxRetryAttempts is the maximum number of retry attempts for failed operations
	MaxRetryAttempts = 3

	// DedupTableMaxSize is the maximum size of the deduplication hash table
	// to prevent unbounded memory growth
	DedupTableMaxSize = 10000

	// PacketBufferTTL is how long to keep incomplete packet buffers before cleanup
	PacketBufferTTL = 5 * time.Minute

	// MaxMultipartPackets is the maximum number of packets in a multipart message
	MaxMultipartPackets = 1000
)
