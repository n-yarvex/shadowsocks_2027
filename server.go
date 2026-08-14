package main

import (
	"bytes"
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lukechampine.com/blake3"
)

type ServerSession struct {
	PfsKey     []byte
	Expire     time.Time
	NfsKeys    sync.Map
	NfsKeysCnt int32
	TicketID   [16]byte
}

type ServerInstance struct {
	NfsSKeys      []any
	NfsPKeysBytes [][]byte
	Hash32s       [][32]byte
	RelaysLength  int
	Sessions      map[[16]byte]*ServerSession
	Tickets       [][16]byte
	Lasts         map[int64][][16]byte
	Closed        bool
	RWLock        sync.RWMutex
	rateLim       sync.Map
}

func (i *ServerInstance) Init(nfsSKeysBytes [][]byte) error {
	if i.NfsSKeys != nil {
		return fmt.Errorf("already initialized")
	}
	l := len(nfsSKeysBytes)
	if l == 0 {
		return fmt.Errorf("empty")
	}
	i.NfsSKeys = make([]any, l)
	i.NfsPKeysBytes = make([][]byte, l)
	i.Hash32s = make([][32]byte, l)
	for j, k := range nfsSKeysBytes {
		if len(k) == x25519KeySize {
			priv, err := ecdh.X25519().NewPrivateKey(k)
			if err != nil {
				return err
			}
			i.NfsSKeys[j] = priv
			i.NfsPKeysBytes[j] = priv.PublicKey().Bytes()
			i.RelaysLength += x25519KeySize + x25519KeySize
		} else {
			dk, err := mlkem.NewDecapsulationKey768(k)
			if err != nil {
				return err
			}
			i.NfsSKeys[j] = dk
			i.NfsPKeysBytes[j] = dk.EncapsulationKey().Bytes()
			i.RelaysLength += mlkemCTSize + x25519KeySize
		}
		i.Hash32s[j] = blake3.Sum256(i.NfsPKeysBytes[j])
	}
	i.RelaysLength -= x25519KeySize
	i.Sessions = make(map[[16]byte]*ServerSession)
	i.Tickets = make([][16]byte, 0, 1024)
	i.Lasts = make(map[int64][][16]byte)
	go i.cleanup()
	return nil
}

func (i *ServerInstance) cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		<-ticker.C
		i.RWLock.Lock()
		if i.Closed {
			i.RWLock.Unlock()
			return
		}
		now := time.Now()
		minute := now.Unix() / 60
		lasts := i.Lasts[minute]
		for _, key := range lasts {
			delete(i.Sessions, key)
			for j, t := range i.Tickets {
				if t == key {
					i.Tickets = append(i.Tickets[:j], i.Tickets[j+1:]...)
					break
				}
			}
		}
		delete(i.Lasts, minute)
		delete(i.Lasts, minute-1)
		i.RWLock.Unlock()
	}
}

func (i *ServerInstance) Close() error {
	i.RWLock.Lock()
	i.Closed = true
	i.RWLock.Unlock()
	return nil
}

func (i *ServerInstance) rateCheck(addr string) bool {
	now := time.Now().Unix()
	v, ok := i.rateLim.Load(addr)
	if ok {
		if now-v.(int64) < 5 {
			return false
		}
	}
	i.rateLim.Store(addr, now)
	return true
}

func (i *ServerInstance) Handshake(conn net.Conn) (*CommonConn, error) {
	if i.NfsSKeys == nil {
		return nil, fmt.Errorf("uninitialized")
	}
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	c := NewCommonConn(conn)
	ivAndRelays := make([]byte, 16+i.RelaysLength)
	if _, err := io.ReadFull(conn, ivAndRelays); err != nil {
		return nil, err
	}
	iv := ivAndRelays[:16]
	relays := ivAndRelays[16:]
	var nfsKey []byte
	var lastCTR cipher.Stream
	for j, k := range i.NfsSKeys {
		if lastCTR != nil {
			lastCTR.XORKeyStream(relays, relays[:x25519KeySize])
		}
		idx := x25519KeySize
		if _, ok := k.(*mlkem.DecapsulationKey768); ok {
			idx = mlkemCTSize
		}
		if priv, ok := k.(*ecdh.PrivateKey); ok {
			pub, err := ecdh.X25519().NewPublicKey(relays[:idx])
			if err != nil {
				return nil, err
			}
			if pub.Bytes()[31] > 127 {
				return nil, fmt.Errorf("high bit")
			}
			nfsKey, err = priv.ECDH(pub)
			if err != nil {
				return nil, err
			}
		} else if dk, ok := k.(*mlkem.DecapsulationKey768); ok {
			var err error
			nfsKey, err = dk.Decapsulate(relays[:idx])
			if err != nil {
				return nil, err
			}
		}
		if j == len(i.NfsSKeys)-1 {
			break
		}
		relays = relays[idx:]
		lastCTR = NewCTR(nfsKey, iv)
		lastCTR.XORKeyStream(relays, relays[:x25519KeySize])
		if !bytes.Equal(relays[:x25519KeySize], i.Hash32s[j+1][:]) {
			return nil, fmt.Errorf("hash mismatch")
		}
		relays = relays[x25519KeySize:]
	}
	nfsAEAD := NewAEAD(iv, nfsKey)
	encryptedLength := make([]byte, 18)
	if _, err := io.ReadFull(conn, encryptedLength); err != nil {
		return nil, err
	}
	decryptedLength := make([]byte, 2)
	if _, err := nfsAEAD.Open(decryptedLength[:0], nil, encryptedLength, nil); err != nil {
		return nil, err
	}
	length := DecodeLength(decryptedLength)
	if length == x25519KeySize {
		encryptedTicket := make([]byte, x25519KeySize)
		if _, err := io.ReadFull(conn, encryptedTicket); err != nil {
			return nil, err
		}
		ticket, err := nfsAEAD.Open(nil, nil, encryptedTicket, nil)
		if err != nil {
			return nil, err
		}
		var ticketKey [16]byte
		copy(ticketKey[:], ticket[:16])
		i.RWLock.Lock()
		s, ok := i.Sessions[ticketKey]
		if !ok {
			i.RWLock.Unlock()
			noises := make([]byte, 512)
			if _, err := rand.Read(noises); err != nil {
				log.Printf("rand read noise failed: %v", err)
			}
			if _, err := conn.Write(noises); err != nil {
				log.Printf("write noise failed: %v", err)
			}
			return nil, fmt.Errorf("ticket not found")
		}
		if time.Now().After(s.Expire) {
			i.RWLock.Unlock()
			return nil, fmt.Errorf("ticket expired")
		}
		cnt := atomic.AddInt32(&s.NfsKeysCnt, 1)
		if cnt > maxNfsKeys {
			atomic.AddInt32(&s.NfsKeysCnt, -1)
			i.RWLock.Unlock()
			return nil, fmt.Errorf("replay limit")
		}
		if _, loaded := s.NfsKeys.LoadOrStore([32]byte(nfsKey), true); loaded {
			atomic.AddInt32(&s.NfsKeysCnt, -1)
			i.RWLock.Unlock()
			return nil, fmt.Errorf("replay")
		}
		pfsKey := s.PfsKey
		i.RWLock.Unlock()
		unitedKey := append(pfsKey, nfsKey...)
		c.UnitedKey = unitedKey
		serverRandom := make([]byte, 16)
		if _, err := rand.Read(serverRandom); err != nil {
			return nil, err
		}
		if _, err := conn.Write(serverRandom); err != nil {
			return nil, err
		}
		c.AEAD = NewAEAD(serverRandom, unitedKey)
		c.PeerAEAD = NewAEAD(encryptedTicket, unitedKey)
		return c, nil
	}
	if length < mlkemPubSize+x25519KeySize+aeadOverhead {
		return nil, fmt.Errorf("short length")
	}
	encryptedPfsPublicKey := make([]byte, length)
	if _, err := io.ReadFull(conn, encryptedPfsPublicKey); err != nil {
		return nil, err
	}
	decryptedPfs, err := nfsAEAD.Open(encryptedPfsPublicKey[:0], nil, encryptedPfsPublicKey, nil)
	if err != nil {
		return nil, err
	}
	mlkem768EKey, err := mlkem.NewEncapsulationKey768(decryptedPfs[:mlkemPubSize])
	if err != nil {
		return nil, err
	}
	mlkem768Key, encapsulatedPfsKey := mlkem768EKey.Encapsulate()
	peerX25519PKey, err := ecdh.X25519().NewPublicKey(decryptedPfs[mlkemPubSize : mlkemPubSize+x25519KeySize])
	if err != nil {
		return nil, err
	}
	x25519SKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	x25519Key, err := x25519SKey.ECDH(peerX25519PKey)
	if err != nil {
		return nil, err
	}
	pfsKey := make([]byte, x25519KeySize+x25519KeySize)
	copy(pfsKey, mlkem768Key)
	copy(pfsKey[x25519KeySize:], x25519Key)
	serverPfsPublicKey := append(encapsulatedPfsKey, x25519SKey.PublicKey().Bytes()...)
	unitedKey := append(pfsKey, nfsKey...)
	c.UnitedKey = unitedKey
	c.AEAD = NewAEAD(serverPfsPublicKey, unitedKey)
	clientPfsPublicKey := decryptedPfs[:mlkemPubSize+x25519KeySize]
	c.PeerAEAD = NewAEAD(clientPfsPublicKey, unitedKey)

	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	seconds, err := randBetween(50, 60)
	if err != nil {
		seconds = 60
	}
	expireTime := time.Now().Add(time.Duration(seconds) * time.Second)
	payload := make([]byte, 2+16)
	copy(payload, EncodeLength(int(seconds)))
	copy(payload[2:], id[:])

	var ticketKey [16]byte
	copy(ticketKey[:], payload[:16])

	i.RWLock.Lock()
	cleanupMinute := time.Now().Add(2 * time.Minute).Unix() / 60
	i.Lasts[cleanupMinute] = append(i.Lasts[cleanupMinute], ticketKey)
	i.Tickets = append(i.Tickets, ticketKey)
	i.Sessions[ticketKey] = &ServerSession{
		PfsKey:     pfsKey,
		Expire:     expireTime,
		NfsKeys:    sync.Map{},
		NfsKeysCnt: 0,
		TicketID:   id,
	}
	i.RWLock.Unlock()

	sealedTicket := c.AEAD.Seal(nil, nil, payload, nil)
	serverHello := make([]byte, mlkemCTSize+x25519KeySize+aeadOverhead+x25519KeySize)
	sealedPfs := nfsAEAD.Seal(nil, nil, serverPfsPublicKey, nil)
	copy(serverHello[:mlkemCTSize+x25519KeySize+aeadOverhead], sealedPfs)
	copy(serverHello[mlkemCTSize+x25519KeySize+aeadOverhead:], sealedTicket)
	if _, err := conn.Write(serverHello); err != nil {
		return nil, err
	}
	return c, nil
}

func NewServerConn(conn net.Conn, cfg *Config) (*FakeHTTPConn, error) {
	fc := &FakeHTTPConn{
		RawConn:  NewRawConn(conn),
		host:     cfg.Host,
		isClient: false,
		chunkBuf: make([]byte, 0, 64*1024),
	}
	if err := fc.serverHandshake(); err != nil {
		return nil, err
	}
	return fc, nil
}

func (c *FakeHTTPConn) serverHandshake() error {
	header, err := c.ReadUntilBlank()
	if err != nil {
		return err
	}
	lines := strings.Split(header, "\r\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "GET ") {
		return fmt.Errorf("not GET")
	}
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
	if _, err := c.WriteString(resp); err != nil {
		return err
	}
	c.handshake = true
	return nil
}

func readTarget(r io.Reader) (string, int, error) {
	tb := make([]byte, 1)
	if _, err := io.ReadFull(r, tb); err != nil {
		return "", 0, err
	}
	switch tb[0] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(r, port); err != nil {
			return "", 0, err
		}
		return net.IP(ip).String(), int(binary.BigEndian.Uint16(port)), nil
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return "", 0, err
		}
		domain := make([]byte, lb[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", 0, err
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(r, port); err != nil {
			return "", 0, err
		}
		return string(domain), int(binary.BigEndian.Uint16(port)), nil
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(r, port); err != nil {
			return "", 0, err
		}
		return net.IP(ip).String(), int(binary.BigEndian.Uint16(port)), nil
	default:
		return "", 0, fmt.Errorf("unsupported type %d", tb[0])
	}
}

func doPoWServer(raw net.Conn, diff int) error {
	raw.SetReadDeadline(time.Now().Add(8 * time.Second))
	defer raw.SetReadDeadline(time.Time{})
	chal := make([]byte, 32)
	if _, err := rand.Read(chal); err != nil {
		return err
	}
	if _, err := raw.Write(chal); err != nil {
		return err
	}
	buf := make([]byte, 64)
	if _, err := io.ReadFull(raw, buf); err != nil {
		return err
	}
	nonce, proof := buf[:32], buf[32:]
	h := sha256.Sum256(append(append(chal, nonce...), proof...))
	for i := 0; i < diff; i++ {
		if h[i] != 0 {
			raw.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			raw.Close()
			return fmt.Errorf("invalid proof")
		}
	}
	return nil
}

func main() {
	cfg, err := LoadConfig("server.json")
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	server := &ServerInstance{}
	if err := server.Init(cfg.Keys); err != nil {
		log.Fatalf("init: %v", err)
	}
	ln, err := net.Listen("tcp", cfg.IP+":"+strconv.Itoa(cfg.Port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	for {
		raw, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()
			if !server.rateCheck(conn.RemoteAddr().String()) {
				return
			}
			httpConn, err := NewServerConn(conn, cfg)
			if err != nil {
				log.Printf("HTTP server handshake failed: %v", err)
				return
			}
			defer httpConn.Close()
			if err := doPoWServer(httpConn.RawConn.Conn, cfg.PowDifficulty); err != nil {
				log.Printf("PoW validation failed: %v", err)
				return
			}
			sudokuConn, err := NewPackedTCPConn(httpConn, cfg.UUID)
			if err != nil {
				log.Printf("Packed TCP init failed: %v", err)
				return
			}
			encConn, err := server.Handshake(sudokuConn)
			if err != nil {
				log.Printf("Handshake failed: %v", err)
				return
			}
			host, port, err := readTarget(encConn)
			if err != nil {
				log.Printf("Read target failed: %v", err)
				return
			}
			target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				log.Printf("Dial target failed: %v", err)
				return
			}
			defer target.Close()
			log.Printf("Proxy established to %s:%d", host, port)
			done := make(chan struct{})
			go func() {
				io.Copy(target, encConn)
				target.Close()
				close(done)
			}()
			io.Copy(encConn, target)
			encConn.Close()
			<-done
		}(raw)
	}
}