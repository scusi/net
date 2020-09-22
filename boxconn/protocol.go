package boxconn

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
	"log"
	"math/rand"
)

const (
	lenSize   = 8
	nonceSize = 24
	keySize   = 32
)

type (
	Protocol struct {
		reader                                    Reader
		writer                                    Writer
		myNonce, peerNonce                        [nonceSize]byte
		privateKey, publicKey, peerKey, sharedKey [keySize]byte
	}
	Message struct {
		Nonce [nonceSize]byte
		Data  []byte
	}
	Reader interface {
		ReadMessage() (Message, error)
	}
	ReaderFunc func() (Message, error)
	Writer     interface {
		WriteMessage(Message) error
	}
	WriterFunc func(Message) error
)

func (rf ReaderFunc) ReadMessage() (Message, error) {
	return rf()
}
func (wf WriterFunc) WriteMessage(msg Message) error {
	return wf(msg)
}

var zeroNonce [nonceSize]byte

// Generate a nonce: timestamp (uuid) + random
func generateNonce() [nonceSize]byte {
	var nonce [nonceSize]byte
	copy(nonce[:16], uuid.New().String())
	binary.BigEndian.PutUint64(nonce[16:], uint64(rand.Int63()))
	log.Printf("genNonce: %x\n", nonce)
	return nonce
}

// The next nonce (incremented big-endianly)
func incrementNonce(nonce [nonceSize]byte) [nonceSize]byte {
	for i := nonceSize - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
	log.Printf("incr nonce: %x\n", nonce)
	return nonce
}

func NewProtocol(r Reader, w Writer) *Protocol {
	return &Protocol{
		reader: r,
		writer: w,
	}
}

// Handshake establishes a session between two parties. Keys can be generated
// using box.GenerateKeys. allowedKeys is a list of keys which are allowed
// for the session.
func (p *Protocol) Handshake(privateKey, publicKey [keySize]byte, allowedKeys ...[keySize]byte) error {
	p.privateKey = privateKey
	p.publicKey = publicKey

	// write our nonce & public key
	err := p.WriteRaw(publicKey[:])
	if err != nil {
		return err
	}

	// read the client's nonce & public key
	data, err := p.ReadRaw()
	if err != nil {
		return err
	}
	var peerKey [keySize]byte
	copy(peerKey[:], data)
	p.peerKey = peerKey
	fmt.Printf("PRIVATE KEY: %x\n", privateKey)
	fmt.Printf("PEER KEY: %x\n", peerKey)

	// verify that this is a key we allow
	allow := false
	for _, k := range allowedKeys {
		if bytes.Equal(k[:], peerKey[:]) {
			allow = true
			break
		}
	}
	if !allow {
		return fmt.Errorf("key not allowed: %x", peerKey[:])
	}

	// compute a shared key we can use for the rest of the session
	box.Precompute(&p.sharedKey, &peerKey, &privateKey)
	fmt.Printf("SHARED KEY: %x\n", p.sharedKey)

	// now to prevent replay attacks we trade session tokens
	token := []byte(uuid.New().String())
	err = p.Write(token)
	if err != nil {
		return err
	}

	// read peer session token
	peerToken, err := p.Read()
	if err != nil {
		return err
	}

	// send the peer session token back
	err = p.Write(peerToken)
	if err != nil {
		return err
	}

	// read the response
	receivedToken, err := p.Read()
	if err != nil {
		return err
	}

	if !bytes.Equal(token, receivedToken) {
		return fmt.Errorf("invalid session token")
	}

	return nil
}

// ReadRaw reads a message from the reader, checks its nonce
//   value, but does not decrypt it
func (p *Protocol) ReadRaw() ([]byte, error) {
	msg, err := p.reader.ReadMessage()
	if err != nil {
		return nil, err
	}
	if p.peerNonce == zeroNonce {
		p.peerNonce = msg.Nonce
		log.Printf("peerNonce is zeroNonce\n")
	} else {
		p.peerNonce = incrementNonce(p.peerNonce)
		log.Printf("peerNonce is: %x, going to increment\n", p.peerNonce)
	}

	if !bytes.Equal(msg.Nonce[:], p.peerNonce[:]) {
		return nil, fmt.Errorf("invalid nonce")
	}

	fmt.Printf("READ RAW: %x\n", msg.Data)

	return msg.Data, nil
}

// Read reads a raw message from the reader, then decrypts it
func (p *Protocol) Read() ([]byte, error) {
	sealed, err := p.ReadRaw()
	if err != nil {
		return nil, err
	}

	unsealed, ok := box.Open(nil, sealed, &p.peerNonce, &p.peerKey, &p.privateKey)
	if !ok {
		return nil, fmt.Errorf("error decrypting message, nonce: %x\n", p.peerNonce)
	}

	fmt.Printf("READ: %x\n", unsealed)

	return unsealed, nil
}

// WriteRaw writes the data (unsealed) to the writer and increments the nonce
func (p *Protocol) WriteRaw(data []byte) error {
	if p.myNonce == zeroNonce {
		p.myNonce = generateNonce()
	} else {
		p.myNonce = incrementNonce(p.myNonce)
	}

	fmt.Printf("WRITE RAW: %x\n", data)

	return p.writer.WriteMessage(Message{
		Nonce: p.myNonce,
		Data:  data,
	})
}

// Write writes the data (sealed) to the writer and increments the nonce
func (p *Protocol) Write(unsealed []byte) error {
	if p.myNonce == zeroNonce {
		p.myNonce = generateNonce()
	} else {
		p.myNonce = incrementNonce(p.myNonce)
	}

	sealed := box.Seal(nil, unsealed, &p.myNonce, &p.peerKey, &p.sharedKey)

	fmt.Printf("WRITE: %x\nnonce used: %x\n", sealed, p.myNonce)

	return p.writer.WriteMessage(Message{
		Nonce: p.myNonce,
		Data:  sealed,
	})
}
