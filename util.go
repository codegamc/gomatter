package gomatter

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

func CreateRandomBytes(n int) []byte {
	out := make([]byte, n)
	rand.Read(out)
	return out
}

func idToBytes(id uint64) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, id)
	return b.Bytes()
}

func hmacSHA256Enc(in []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(in)
	return mac.Sum(nil)
}

func sha256Enc(in []byte) []byte {
	s := sha256.New()
	s.Write(in)
	return s.Sum(nil)
}

func hkdfSHA256(secret, salt, info []byte, size int) []byte {
	engine := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, size)
	if _, err := io.ReadFull(engine, key); err != nil {
		return []byte{}
	}
	return key
}
