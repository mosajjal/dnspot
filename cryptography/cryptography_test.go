package cryptography

import (
	"bytes"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	
	if key == nil {
		t.Error("GenerateKey() returned nil key")
	}
	
	if len(key.D) == 0 {
		t.Error("GenerateKey() returned empty key")
	}
}

func TestGenerateKeypair(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	
	if pub == "" {
		t.Error("GenerateKeypair() returned empty public key")
	}
	
	if priv == "" {
		t.Error("GenerateKeypair() returned empty private key")
	}
	
	if pub == PublicKeyStr(priv) {
		t.Error("Public and private keys should be different")
	}
}

func TestKeyConversion(t *testing.T) {
	// Generate a keypair
	_, privStr, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	
	// Convert string back to key
	priv, err := PrivateKeyFromString(string(privStr))
	if err != nil {
		t.Fatalf("PrivateKeyFromString() error = %v", err)
	}
	
	// Convert back to string
	privStr2 := priv.String()
	
	if privStr != privStr2 {
		t.Error("Private key conversion not symmetric")
	}
}

func TestPublicKeyFromPrivate(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	
	pub := priv.GetPublicKey()
	
	if pub.X == nil || pub.Y == nil {
		t.Error("GetPublicKey() returned invalid public key")
	}
	
	if pub.Curve == nil {
		t.Error("GetPublicKey() returned nil curve")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	// Generate two keypairs
	alice, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	
	bob, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	
	bobPub := bob.GetPublicKey()
	
	// Test data
	plaintext := []byte("Hello, World!")
	
	// Alice encrypts for Bob
	ciphertext, err := alice.Encrypt(&bobPub, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	
	if len(ciphertext) == 0 {
		t.Error("Encrypt() returned empty ciphertext")
	}
	
	// Bob decrypts
	decrypted, err := bob.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypt() = %v, want %v", decrypted, plaintext)
	}
}

func TestEncryptDecryptLargeData(t *testing.T) {
	alice, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	
	bob, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	
	bobPub := bob.GetPublicKey()
	
	// Large test data
	plaintext := make([]byte, 1000)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	
	ciphertext, err := alice.Encrypt(&bobPub, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	
	decrypted, err := bob.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted data doesn't match original")
	}
}

func TestDecryptInvalidData(t *testing.T) {
	bob, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	
	// Try to decrypt garbage
	_, err = bob.Decrypt([]byte("garbage data"))
	if err == nil {
		t.Error("Decrypt() should fail on invalid data")
	}
	
	// Try to decrypt empty data
	_, err = bob.Decrypt([]byte{})
	if err == nil {
		t.Error("Decrypt() should fail on empty data")
	}
}

func TestEncryptInvalidKey(t *testing.T) {
	alice, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	
	// Try to encrypt with nil public key
	_, err = alice.Encrypt(nil, []byte("test"))
	if err == nil {
		t.Error("Encrypt() should fail with nil public key")
	}
	
	// Try to encrypt empty data
	bobPub := alice.GetPublicKey()
	_, err = alice.Encrypt(&bobPub, []byte{})
	if err == nil {
		t.Error("Encrypt() should fail with empty data")
	}
}

func TestPublicKeyString(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	
	pub := key.GetPublicKey()
	pubStr := pub.String()
	
	if pubStr == "" {
		t.Error("PublicKey.String() returned empty string")
	}
	
	// Convert back
	pub2, err := PublicKeyFromString(pubStr)
	if err != nil {
		t.Fatalf("PublicKeyFromString() error = %v", err)
	}
	
	// Should be able to encrypt/decrypt with reconstructed key
	plaintext := []byte("test")
	ciphertext, err := key.Encrypt(pub2, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() with reconstructed key error = %v", err)
	}
	
	decrypted, err := key.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Encryption with reconstructed key failed")
	}
}

func TestGetPublicKeyFromMessage(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	
	pub := key.GetPublicKey()
	
	// Create a message (simulate encrypted message)
	plaintext := []byte("test message")
	ciphertext, err := key.Encrypt(&pub, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	
	// Extract public key from message
	extractedPub := GetPublicKeyFromMessage(ciphertext)
	
	if extractedPub == nil {
		t.Error("GetPublicKeyFromMessage() returned nil")
	}
	
	if extractedPub.X == nil || extractedPub.Y == nil {
		t.Error("GetPublicKeyFromMessage() returned invalid public key")
	}
}

// Benchmark tests
func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey()
	}
}

func BenchmarkEncrypt(b *testing.B) {
	alice, _ := GenerateKey()
	bob, _ := GenerateKey()
	bobPub := bob.GetPublicKey()
	data := []byte("benchmark data for encryption testing")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alice.Encrypt(&bobPub, data)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	alice, _ := GenerateKey()
	bob, _ := GenerateKey()
	bobPub := bob.GetPublicKey()
	data := []byte("benchmark data for decryption testing")
	ciphertext, _ := alice.Encrypt(&bobPub, data)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bob.Decrypt(ciphertext)
	}
}
