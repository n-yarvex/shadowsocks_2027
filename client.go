package main

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"lukechampine.com/blake3"
)

type ClientInstance struct {
	NfsPKeys      []any
	NfsPKeysBytes [][]byte
	Hash32s       [][32]byte
	RelaysLength  int
	Ticket        []byte
	PfsKey        []byte
	Expire        time.Time
	RWLock        sync.RWMutex
}

func (i *ClientInstance) Init(nfsPKeysBytes [][]byte) error {
	if i.NfsPKeys != nil {
		return fmt.Errorf("already initialized")
	}
	l := len(nfsPKeysBytes)
	if l == 0 {
		return fmt.Errorf("empty nfsPKeysBytes")
	}
	i.NfsPKeys = make([]any, l)
	i.NfsPKeysBytes = nfsPKeysBytes
	i.Hash32s = make([][32]byte, l)
	var err error
	for j, k := range nfsPKeysBytes {
		if len(k) == x25519KeySize {
			var pub *ecdh.PublicKey
			pub, err = ecdh.X25519().NewPublicKey(k)
			if err != nil {
				return err
			}
			i.NfsPKeys[j] = pub
			i.RelaysLength += x25519KeySize + x25519KeySize
		} else {
			var ek *mlkem.EncapsulationKey768
			ek, err = mlkem.NewEncapsulationKey768(k)
			if err != nil {
				return err
			}
			i.NfsPKeys[j] = ek
			i.RelaysLength += mlkemCTSize + x25519KeySize
		}
		i.Hash32s[j] = blake3.Sum256(k)
	}
	i.RelaysLength -= x25519KeySize
	return nil
}

func (i *ClientInstance) Handshake(conn net.Conn) (*CommonConn, error) {
	if i.NfsPKeys == nil {
		return nil, fmt.Errorf("uninitialized")
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	c := NewCommonConn(conn)
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	relaysTotal := 16 + i.RelaysLength
	relaysBuf := make([]byte, i.RelaysLength)
	relays := relaysBuf
	var nfsKey []byte
	var lastCTR cipher.Stream
	for j, k := range i.NfsPKeys {
		idx := x25519KeySize
		if pub, ok := k.(*ecdh.PublicKey); ok {
			pk, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return nil, err
			}
			copy(relays, pk.PublicKey().Bytes())
			nfsKey, err = pk.ECDH(pub)
			if err != nil {
				return nil, err
			}
		} else if ek, ok := k.(*mlkem.EncapsulationKey768); ok {
			ct, err := ek.Encapsulate()
			if err != nil {
				return nil, err
			}
			copy(relays, ct)
			idx = mlkemCTSize
		}
		if lastCTR != nil {
			lastCTR.XORKeyStream(relays, relays[:x25519KeySize])
		}
		if j == len(i.NfsPKeys)-1 {
			break
		}
		lastCTR = NewCTR(nfsKey, iv)
		lastCTR.XORKeyStream(relays[idx:], i.Hash32s[j+1][:])
		relays = relays[idx+x25519KeySize:]
	}
	nfsAEAD := NewAEAD(iv, nfsKey)
	i.RWLock.RLock()
	ticket := i.Ticket
	expire := i.Expire
	pfsKey := i.PfsKey
	i.RWLock.RUnlock()
	if ticket != nil && time.Now().Before(expire) {
		unitedKey := append(pfsKey, nfsKey...)
		c.UnitedKey = unitedKey
		clientHello := make([]byte, relaysTotal+18+x25519KeySize)
		copy(clientHello, iv)
		copy(clientHello[16:relaysTotal], relaysBuf)
		sealedLen := nfsAEAD.Seal(nil, nil, EncodeLength(x25519KeySize), nil)
		copy(clientHello[relaysTotal:relaysTotal+18], sealedLen)
		sealedTicket := nfsAEAD.Seal(nil, nil, ticket, nil)
		copy(clientHello[relaysTotal+18:relaysTotal+18+x25519KeySize], sealedTicket)
		if _, err := conn.Write(clientHello); err != nil {
			return nil, err
		}
		c.AEAD = NewAEAD(clientHello[relaysTotal+18:relaysTotal+18+x25519KeySize], unitedKey)
		return c, nil
	}
	clientHello := make([]byte, relaysTotal+18+mlkemPubSize+x25519KeySize+aeadOverhead)
	copy(clientHello, iv)
	copy(clientHello[16:relaysTotal], relaysBuf)
	pfsKeyExchangeLength := 18 + mlkemPubSize + x25519KeySize + aeadOverhead
	sealedLen := nfsAEAD.Seal(nil, nil, EncodeLength(pfsKeyExchangeLength-18), nil)
	copy(clientHello[relaysTotal:relaysTotal+18], sealedLen)
	mlkemDKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	x25519SKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	clientPfsPublicKey := append(mlkemDKey.EncapsulationKey().Bytes(), x25519SKey.PublicKey().Bytes()...)
	sealedPfs := nfsAEAD.Seal(nil, nil, clientPfsPublicKey, nil)
	copy(clientHello[relaysTotal+18:relaysTotal+18+mlkemPubSize+x25519KeySize+aeadOverhead], sealedPfs)
	if _, err := conn.Write(clientHello); err != nil {
		return nil, err
	}
	encryptedPfsPublicKey := make([]byte, mlkemCTSize+x25519KeySize+aeadOverhead)
	if _, err := io.ReadFull(conn, encryptedPfsPublicKey); err != nil {
		return nil, err
	}
	decryptedPfs, err := nfsAEAD.Open(encryptedPfsPublicKey[:0], nil, encryptedPfsPublicKey, nil)
	if err != nil {
		return nil, err
	}
	mlkem768Key, err := mlkemDKey.Decapsulate(decryptedPfs[:mlkemCTSize])
	if err != nil {
		return nil, err
	}
	peerX25519PKey, err := ecdh.X25519().NewPublicKey(decryptedPfs[mlkemCTSize : mlkemCTSize+x25519KeySize])
	if err != nil {
		return nil, err
	}
	x25519Key, err := x25519SKey.ECDH(peerX25519PKey)
	if err != nil {
		return nil, err
	}
	pfsKey = make([]byte, x25519KeySize+x25519KeySize)
	copy(pfsKey, mlkem768Key)
	copy(pfsKey[x25519KeySize:], x25519Key)
	unitedKey := append(pfsKey, nfsKey...)
	c.UnitedKey = unitedKey
	c.AEAD = NewAEAD(clientPfsPublicKey, unitedKey)
	serverPfsPublicKey := decryptedPfs[:mlkemCTSize+x25519KeySize]
	c.PeerAEAD = NewAEAD(serverPfsPublicKey, unitedKey)
	encryptedTicket := make([]byte, x25519KeySize)
	if _, err := io.ReadFull(conn, encryptedTicket); err != nil {
		return nil, err
	}
	ticket, err = c.PeerAEAD.Open(nil, nil, encryptedTicket, nil)
	if err != nil {
		return nil, err
	}
	seconds := DecodeLength(ticket)
	if seconds > 0 {
		i.RWLock.Lock()
		i.Expire = time.Now().Add(time.Duration(seconds) * time.Second)
		i.PfsKey = pfsKey
		i.Ticket = ticket[:16]
		i.RWLock.Unlock()
	}
	return c, nil
}

func NewClientConn(conn net.Conn, cfg *Config) (*FakeHTTPConn, error) {
	fc := &FakeHTTPConn{
		RawConn:   NewRawConn(conn),
		host:      cfg.Host,
		userAgent: cfg.UserAgent,
		isClient:  true,
		chunkBuf:  make([]byte, 0, 64*1024),
	}
	if err := fc.clientHandshake(); err != nil {
		return nil, err
	}
	return fc, nil
}

func (c *FakeHTTPConn) clientHandshake() error {
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n", c.host, c.userAgent)
	if _, err := c.WriteString(req); err != nil {
		return err
	}
	status, err := c.ReadLine()
	if err != nil {
		return err
	}
	if !strings.Contains(status, "200 OK") {
		return fmt.Errorf("unexpected status: %s", status)
	}
	for {
		line, err := c.ReadLine()
		if err != nil {
			return err
		}
		if line == "" {
			break
		}
	}
	c.handshake = true
	return nil
}

func sendTarget(w io.Writer, host string, port int) error {
	ip := net.ParseIP(host)
	var typ byte
	var addr []byte
	if ip == nil {
		typ = 0x03
		addr = []byte(host)
		if len(addr) > 255 {
			return fmt.Errorf("domain too long")
		}
	} else if ip.To4() != nil {
		typ = 0x01
		addr = ip.To4()
	} else {
		typ = 0x04
		addr = ip.To16()
	}
	buf := make([]byte, 0, 1+1+len(addr)+2)
	buf = append(buf, typ)
	if typ == 0x03 {
		buf = append(buf, byte(len(addr)))
	}
	buf = append(buf, addr...)
	buf = append(buf, byte(port>>8), byte(port&0xff))
	_, err := w.Write(buf)
	return err
}

func doPoWClient(raw net.Conn, diff int) error {
	raw.SetReadDeadline(time.Now().Add(8 * time.Second))
	defer raw.SetReadDeadline(time.Time{})
	chal := make([]byte, 32)
	if _, err := io.ReadFull(raw, chal); err != nil {
		return err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	var proof [32]byte
	for {
		h := sha256.Sum256(append(append(chal, nonce...), proof[:]...))
		ok := true
		for i := 0; i < diff; i++ {
			if h[i] != 0 {
				ok = false
				break
			}
		}
		if ok {
			break
		}
		v := binary.LittleEndian.Uint64(proof[:])
		v++
		binary.LittleEndian.PutUint64(proof[:], v)
	}
	_, err := raw.Write(append(nonce, proof[:]...))
	return err
}

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: %s <host> <port>", os.Args[0])
	}
	targetHost := os.Args[1]
	targetPort, err := strconv.Atoi(os.Args[2])
	if err != nil || targetPort < 1 || targetPort > 65535 {
		log.Fatalf("invalid port")
	}
	cfg, err := LoadConfig("client.json")
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	client := &ClientInstance{}
	if err := client.Init(cfg.Keys); err != nil {
		log.Fatalf("init: %v", err)
	}
	raw, err := net.Dial("tcp", cfg.IP+":"+strconv.Itoa(cfg.Port))
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	httpConn, err := NewClientConn(raw, cfg)
	if err != nil {
		log.Fatalf("http: %v", err)
	}
	defer httpConn.Close()
	if err := doPoWClient(httpConn.RawConn.Conn, cfg.PowDifficulty); err != nil {
		log.Fatalf("pow: %v", err)
	}
	sudokuConn, err := NewPackedTCPConn(httpConn, cfg.UUID)
	if err != nil {
		log.Fatalf("packed: %v", err)
	}
	encConn, err := client.Handshake(sudokuConn)
	if err != nil {
		log.Fatalf("handshake: %v", err)
	}
	if err := sendTarget(encConn, targetHost, targetPort); err != nil {
		log.Fatalf("send target: %v", err)
	}
	go func() {
		if _, err := io.Copy(encConn, os.Stdin); err != nil {
			encConn.Close()
		}
	}()
	if _, err := io.Copy(os.Stdout, encConn); err != nil {
		encConn.Close()
	}
}