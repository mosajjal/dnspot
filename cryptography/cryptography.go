package cryptography

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct {
	D []byte
}

var Algorithm = elliptic.P256()

func Encrypt(key crypto.PublicKey, signature crypto.PrivateKey, data []byte) (encrypted []byte, err error) {
	if len(data) < 1 {
		err = errors.New("empty data")
		return
	}
	public := key.(*PublicKey)
	if public == nil {
		err = errors.New("invalid public key")
		return
	}

	private := signature.(*PrivateKey)
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
func Decrypt(key crypto.PrivateKey, data []byte) (decrypted []byte, err error) {
	if len(data) < 82 {
		err = errors.New("invalid data size")
		return
	}
	private := key.(*PrivateKey)
	if private == nil {
		err = errors.New("invalid private key")
		return
	}
	buf := bytes.Buffer{}
	x, y := elliptic.UnmarshalCompressed(Algorithm, data[0:33])

	sym, _ := Algorithm.ScalarMult(x, y, private.D)
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

func (key PrivateKey) String() string {
	return EncodeBytes(key.D)
}
func (key PublicKey) String() string {
	return EncodeBytes(elliptic.MarshalCompressed(key.Curve, key.X, key.Y))
}

func (key PrivateKey) GetPublicKey() PublicKey {
	x, y := Algorithm.ScalarBaseMult(key.D)
	return PublicKey{
		Curve: Algorithm,
		X:     x,
		Y:     y,
	}
}

func PublicKeyFromString(public string) (*PublicKey, error) {
	publicKey := DecodeToBytes(public)

	// if err != nil {
	// 	return nil, err
	// }
	x, y := elliptic.UnmarshalCompressed(Algorithm, publicKey)
	if x == nil || y == nil {
		return nil, errors.New("invalid public key")
	}
	return &PublicKey{
		Curve: Algorithm,
		X:     x,
		Y:     y,
	}, nil
}

func PrivateKeyFromString(private string) (*PrivateKey, error) {
	d := DecodeToBytes(private)
	// if err != nil {
	// 	return nil, err
	// }
	return &PrivateKey{
		D: d,
	}, nil
}

func GenerateKey() (*PrivateKey, error) {
	d, _, _, err := elliptic.GenerateKey(Algorithm, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		D: d,
	}, nil
}

func GetPublicKeyFromMessage(msg []byte) *PublicKey {
	x, y := elliptic.UnmarshalCompressed(Algorithm, msg[0:33])
	return &PublicKey{
		Curve: Algorithm,
		X:     x,
		Y:     y,
	}
}
