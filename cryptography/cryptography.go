package cryptography

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// PublicKey has the curve and the X,Y.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}
type PublicKeyStr string

// PrivateKey is a bytestream of data not converted to anything
type PrivateKey struct {
	D []byte
}
type PrivateKeyStr string

var algorithm = elliptic.P256()

// Encrypt will provide a encryption mechanism for an arbitrary bytestream
func (private *PrivateKey) Encrypt(public *PublicKey, data []byte) (encrypted []byte, err error) {
	if len(data) < 1 {
		err = errors.New("empty data")
		return
	}
	if public == nil {
		err = errors.New("invalid public key")
		return
	}

	pub := private.GetPublicKey()
	ephemeral := elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y)
	sym, _ := public.Curve.ScalarMult(public.X, public.Y, private.D)
	// Create buffer
	buf := bytes.Buffer{}
	_, err = buf.Write(sym.Bytes())
	if err != nil {
		return
	}
	_, err = buf.Write([]byte{0x00, 0x00, 0x00, 0x01})
	if err != nil {
		return
	}
	_, err = buf.Write(ephemeral)
	if err != nil {
		return
	}
	hashed := sha256.Sum256(buf.Bytes())
	buf.Reset()
	block, err := aes.NewCipher(hashed[0:16])
	if err != nil {
		return
	}
	ch, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return
	}
	_, err = buf.Write(ephemeral)
	if err != nil {
		return
	}
	_, err = buf.Write(ch.Seal(nil, hashed[16:], data, nil))
	if err != nil {
		return
	}
	encrypted = buf.Bytes()
	return
}

// Decrypt will provide a decryption mechanism for an arbitrary bytestream
func (private *PrivateKey) Decrypt(data []byte) (decrypted []byte, err error) {
	// with variable length, this is meaningless. however, DNS servers sometimes
	// send a subdomain of our request to the server rather than the full query
	// so some checks need to be in place
	if len(data) < 34 {
		err = errors.New("invalid data size")
		return
	}
	if private == nil {
		err = errors.New("invalid private key")
		return
	}
	buf := bytes.Buffer{}
	x, y := elliptic.UnmarshalCompressed(algorithm, data[0:33])
	if x == nil || y == nil {
		err = errors.New("invalid public key")
		return
	}

	sym, _ := algorithm.ScalarMult(x, y, private.D)
	_, err = buf.Write(sym.Bytes())
	if err != nil {
		return
	}
	_, err = buf.Write([]byte{0x00, 0x00, 0x00, 0x01})
	if err != nil {
		return
	}
	_, err = buf.Write(data[0:33])
	if err != nil {
		return
	}
	hashed := sha256.Sum256(buf.Bytes())
	buf.Reset()

	block, err := aes.NewCipher(hashed[0:16])
	if err != nil {
		return
	}
	ch, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return
	}
	decrypted, err = ch.Open(nil, hashed[16:], data[33:], nil)
	return
}

// String marshaller for private key
func (private PrivateKey) String() PrivateKeyStr {
	return PrivateKeyStr(EncodeBytes(private.D))
}

// String marshaller for public key
func (key PublicKey) String() PublicKeyStr {
	return PublicKeyStr(EncodeBytes(elliptic.MarshalCompressed(key.Curve, key.X, key.Y)))
}

// GetPublicKey returns a PublicKey object from the key
func (private PrivateKey) GetPublicKey() PublicKey {
	x, y := algorithm.ScalarBaseMult(private.D)
	return PublicKey{
		Curve: algorithm,
		X:     x,
		Y:     y,
	}
}

// PublicKeyFromString grabs a public key string and gives out a publickey object
func PublicKeyFromString(public PublicKeyStr) (*PublicKey, error) {
	publicKey := DecodeToBytes(string(public))

	// if err != nil {
	// 	return nil, err
	// }
	x, y := elliptic.UnmarshalCompressed(algorithm, publicKey)
	if x == nil || y == nil {
		return nil, errors.New("invalid public key")
	}
	return &PublicKey{
		Curve: algorithm,
		X:     x,
		Y:     y,
	}, nil
}

// PrivateKeyFromString grabs a private key string and gives out a privatekey object
func PrivateKeyFromString(private string) (*PrivateKey, error) {
	d := DecodeToBytes(private)
	if len(d) == 0 {
		return nil, errors.New("Bad Private Key")
	}
	return &PrivateKey{
		D: d,
	}, nil
}

// GenerateKey generate a new random private key
func GenerateKey() (*PrivateKey, error) {
	d, _, _, err := elliptic.GenerateKey(algorithm, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		D: d,
	}, nil
}

// GenerateKeypair generates a public and private keypair string
func GenerateKeypair() (PublicKeyStr, PrivateKeyStr, error) {

	privateKey, err := GenerateKey()
	if err != nil {
		return "", "", err
	}
	pubKey := privateKey.GetPublicKey()
	return pubKey.String(), privateKey.String(), nil
}

// GetPublicKeyFromMessage is a helper function to extract first 32 bytes
// from a long message, and provide the sender public key of it
func GetPublicKeyFromMessage(msg []byte) *PublicKey {
	x, y := elliptic.UnmarshalCompressed(algorithm, msg[0:33])
	return &PublicKey{
		Curve: algorithm,
		X:     x,
		Y:     y,
	}
}
