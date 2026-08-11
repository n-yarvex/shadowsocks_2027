package main

import (
    "bytes"
    "crypto/cipher"
    "crypto/ecdh"
    "crypto/mlkem"
    "crypto/rand"
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
}

type ServerInstance struct {
    NfsSKeys      []any
    NfsPKeysBytes [][]byte
    Hash32s       [][32]byte
    RelaysLength  int
    Sessions      map[[16]byte]*ServerSession
    Tickets       [][16]byte
    Lasts         map[int64][16]byte
    Closed        bool
    RWLock        sync.RWMutex
    handshakeLim  sync.Map
}

func (i *ServerInstance) Init(nfsSKeysBytes [][]byte) error {
    log.Printf("[SERVER-INIT] start")
    if i.NfsSKeys != nil {
        return fmt.Errorf("already initialized")
    }
    l := len(nfsSKeysBytes)
    if l == 0 {
        return fmt.Errorf("empty nfsSKeysBytes")
    }
    i.NfsSKeys = make([]any, l)
    i.NfsPKeysBytes = make([][]byte, l)
    i.Hash32s = make([][32]byte, l)
    for j, k := range nfsSKeysBytes {
        if len(k) == x25519KeySize {
            priv, err := ecdh.X25519().NewPrivateKey(k)
            if err != nil {
                log.Printf("[SERVER-INIT] parse X25519 private error: %v", err)
                return err
            }
            i.NfsSKeys[j] = priv
            i.NfsPKeysBytes[j] = priv.PublicKey().Bytes()
            i.RelaysLength += x25519KeySize + x25519KeySize
            log.Printf("[SERVER-INIT] key %d is X25519 private", j)
        } else {
            dk, err := mlkem.NewDecapsulationKey768(k)
            if err != nil {
                log.Printf("[SERVER-INIT] parse ML-KEM private error: %v", err)
                return err
            }
            i.NfsSKeys[j] = dk
            i.NfsPKeysBytes[j] = dk.EncapsulationKey().Bytes()
            i.RelaysLength += mlkemCTSize + x25519KeySize
            log.Printf("[SERVER-INIT] key %d is ML-KEM private", j)
        }
        i.Hash32s[j] = blake3.Sum256(i.NfsPKeysBytes[j])
    }
    i.RelaysLength -= x25519KeySize
    log.Printf("[SERVER-INIT] relaysLength=%d", i.RelaysLength)
    i.Sessions = make(map[[16]byte]*ServerSession)
    i.Tickets = make([][16]byte, 0, 1024)
    i.Lasts = make(map[int64][16]byte)
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
        last := i.Lasts[minute]
        delete(i.Lasts, minute)
        delete(i.Lasts, minute-1)
        if last != [16]byte{} {
            found := -1
            for j, ticket := range i.Tickets {
                if ticket == last {
                    found = j
                    break
                }
            }
            if found != -1 {
                delete(i.Sessions, last)
                i.Tickets = append(i.Tickets[:found], i.Tickets[found+1:]...)
            }
        }
        i.RWLock.Unlock()
        i.handshakeLim.Range(func(key, value interface{}) bool {
            if now.Sub(value.(time.Time)) > rateCleanupAge {
                i.handshakeLim.Delete(key)
            }
            return true
        })
    }
}

func (i *ServerInstance) Close() error {
    i.RWLock.Lock()
    i.Closed = true
    i.RWLock.Unlock()
    return nil
}

func (i *ServerInstance) checkRate(addr string) bool {
    return true
}

func (i *ServerInstance) Handshake(conn net.Conn) (*CommonConn, error) {
    log.Printf("[SERVER-HANDSHAKE] start")
    if i.NfsSKeys == nil {
        log.Printf("[SERVER-HANDSHAKE] NfsSKeys nil")
        return nil, fmt.Errorf("uninitialized")
    }
    c := NewCommonConn(conn)
    ivAndRelays := make([]byte, 16+i.RelaysLength)
    log.Printf("[SERVER-HANDSHAKE] reading ivAndRelays (%d bytes)", len(ivAndRelays))
    if _, err := io.ReadFull(conn, ivAndRelays); err != nil {
        log.Printf("[SERVER-HANDSHAKE] read ivAndRelays error: %v", err)
        return nil, fmt.Errorf("read iv and relays: %w", err)
    }
    log.Printf("[SERVER-HANDSHAKE] received ivAndRelays: %x", ivAndRelays)
    iv := ivAndRelays[:16]
    relays := ivAndRelays[16:]
    log.Printf("[SERVER-HANDSHAKE] iv: %x", iv)
    log.Printf("[SERVER-HANDSHAKE] relays first32: %x", relays[:32])
    var nfsKey []byte
    var lastCTR cipher.Stream
    for j, k := range i.NfsSKeys {
        log.Printf("[SERVER-HANDSHAKE] processing relay %d", j)
        if lastCTR != nil {
            lastCTR.XORKeyStream(relays, relays[:x25519KeySize])
        }
        index := x25519KeySize
        if _, ok := k.(*mlkem.DecapsulationKey768); ok {
            index = mlkemCTSize
        }
        if priv, ok := k.(*ecdh.PrivateKey); ok {
            log.Printf("[SERVER-HANDSHAKE] relay %d X25519 private", j)
            pub, err := ecdh.X25519().NewPublicKey(relays[:index])
            if err != nil {
                log.Printf("[SERVER-HANDSHAKE] parse X25519 public error: %v", err)
                return nil, fmt.Errorf("parse x25519 public key: %w", err)
            }
            if pub.Bytes()[31] > 127 {
                log.Printf("[SERVER-HANDSHAKE] X25519 high bit not zero")
                return nil, fmt.Errorf("x25519 high bit not zero")
            }
            nfsKey, err = priv.ECDH(pub)
            if err != nil {
                log.Printf("[SERVER-HANDSHAKE] X25519 ECDH error: %v", err)
                return nil, fmt.Errorf("x25519 ECDH: %w", err)
            }
        } else if dk, ok := k.(*mlkem.DecapsulationKey768); ok {
            log.Printf("[SERVER-HANDSHAKE] relay %d ML-KEM private", j)
            var err error
            nfsKey, err = dk.Decapsulate(relays[:index])
            if err != nil {
                log.Printf("[SERVER-HANDSHAKE] ML-KEM decapsulate error: %v", err)
                return nil, fmt.Errorf("mlkem decapsulate: %w", err)
            }
        }
        if j == len(i.NfsSKeys)-1 {
            break
        }
        relays = relays[index:]
        lastCTR = NewCTR(nfsKey, iv)
        lastCTR.XORKeyStream(relays, relays[:x25519KeySize])
        if !bytes.Equal(relays[:x25519KeySize], i.Hash32s[j+1][:]) {
            log.Printf("[SERVER-HANDSHAKE] hash mismatch")
            return nil, fmt.Errorf("hash mismatch")
        }
        relays = relays[x25519KeySize:]
    }
    log.Printf("[SERVER-HANDSHAKE] nfsKey: %x", nfsKey)
    nfsAEAD := NewAEAD(iv, nfsKey)
    encryptedLength := make([]byte, 18)
    if _, err := io.ReadFull(conn, encryptedLength); err != nil {
        log.Printf("[SERVER-HANDSHAKE] read encryptedLength error: %v", err)
        return nil, fmt.Errorf("read encrypted length: %w", err)
    }
    log.Printf("[SERVER-HANDSHAKE] encryptedLength: %x", encryptedLength)
    decryptedLength := make([]byte, 2)
    if _, err := nfsAEAD.Open(decryptedLength[:0], nil, encryptedLength, nil); err != nil {
        log.Printf("[SERVER-HANDSHAKE] decrypt length error: %v", err)
        return nil, fmt.Errorf("decrypt length: %w", err)
    }
    length := DecodeLength(decryptedLength)
    log.Printf("[SERVER-HANDSHAKE] decrypted length: %x (%d)", decryptedLength, length)
    if length == x25519KeySize {
        log.Printf("[SERVER-HANDSHAKE] 0-RTT ticket path")
        encryptedTicket := make([]byte, x25519KeySize)
        if _, err := io.ReadFull(conn, encryptedTicket); err != nil {
            log.Printf("[SERVER-HANDSHAKE] read encryptedTicket error: %v", err)
            return nil, fmt.Errorf("read encrypted ticket: %w", err)
        }
        log.Printf("[SERVER-HANDSHAKE] encryptedTicket: %x", encryptedTicket)
        ticket, err := nfsAEAD.Open(nil, nil, encryptedTicket, nil)
        if err != nil {
            log.Printf("[SERVER-HANDSHAKE] decrypt ticket error: %v", err)
            return nil, fmt.Errorf("decrypt ticket: %w", err)
        }
        log.Printf("[SERVER-HANDSHAKE] decrypted ticket: %x", ticket)
        var ticketKey [16]byte
        copy(ticketKey[:], ticket)
        i.RWLock.RLock()
        s := i.Sessions[ticketKey]
        i.RWLock.RUnlock()
        if s == nil {
            log.Printf("[SERVER-HANDSHAKE] ticket not found")
            noises := make([]byte, 512)
            if _, err := rand.Read(noises); err != nil {
                log.Printf("[SERVER-HANDSHAKE] rand.Read noises error: %v", err)
                return nil, fmt.Errorf("rand read noises: %w", err)
            }
            conn.Write(noises)
            return nil, fmt.Errorf("expired ticket")
        }
        if time.Now().After(s.Expire) {
            log.Printf("[SERVER-HANDSHAKE] ticket expired")
            return nil, fmt.Errorf("ticket expired")
        }
        cnt := atomic.AddInt32(&s.NfsKeysCnt, 1)
        if cnt > maxNfsKeys {
            atomic.AddInt32(&s.NfsKeysCnt, -1)
            return nil, fmt.Errorf("too many replay attempts")
        }
        if _, loaded := s.NfsKeys.LoadOrStore([32]byte(nfsKey), true); loaded {
            atomic.AddInt32(&s.NfsKeysCnt, -1)
            return nil, fmt.Errorf("replay detected")
        }
        unitedKey := append(s.PfsKey, nfsKey...)
        c.UnitedKey = unitedKey
        serverRandom := make([]byte, 16)
        if _, err := rand.Read(serverRandom); err != nil {
            log.Printf("[SERVER-HANDSHAKE] rand.Read serverRandom error: %v", err)
            return nil, fmt.Errorf("rand read server random: %w", err)
        }
        if _, err := conn.Write(serverRandom); err != nil {
            log.Printf("[SERVER-HANDSHAKE] write serverRandom error: %v", err)
            return nil, fmt.Errorf("write server random: %w", err)
        }
        c.AEAD = NewAEAD(serverRandom, unitedKey)
        c.PeerAEAD = NewAEAD(encryptedTicket, unitedKey)
        log.Printf("[SERVER-HANDSHAKE] 0-RTT success")
        return c, nil
    }
    if length < mlkemPubSize+x25519KeySize+aeadOverhead {
        log.Printf("[SERVER-HANDSHAKE] too short length: %d", length)
        return nil, fmt.Errorf("too short length")
    }
    log.Printf("[SERVER-HANDSHAKE] full handshake path")
    encryptedPfsPublicKey := make([]byte, length)
    if _, err := io.ReadFull(conn, encryptedPfsPublicKey); err != nil {
        log.Printf("[SERVER-HANDSHAKE] read encryptedPfsPublicKey error: %v", err)
        return nil, fmt.Errorf("read encrypted pfs key: %w", err)
    }
    log.Printf("[SERVER-HANDSHAKE] encryptedPfsPublicKey: %x", encryptedPfsPublicKey[:64])
    // 修正：使用 nil nonce 自动递增
    if _, err := nfsAEAD.Open(encryptedPfsPublicKey[:0], nil, encryptedPfsPublicKey, nil); err != nil {
        log.Printf("[SERVER-HANDSHAKE] decrypt PFS key error: %v", err)
        return nil, fmt.Errorf("decrypt pfs key: %w", err)
    }
    log.Printf("[SERVER-HANDSHAKE] decrypted PFS key: %x", encryptedPfsPublicKey[:mlkemPubSize+x25519KeySize])
    mlkem768EKey, err := mlkem.NewEncapsulationKey768(encryptedPfsPublicKey[:mlkemPubSize])
    if err != nil {
        log.Printf("[SERVER-HANDSHAKE] parse ML-KEM public error: %v", err)
        return nil, fmt.Errorf("parse mlkem public key: %w", err)
    }
    mlkem768Key, encapsulatedPfsKey := mlkem768EKey.Encapsulate()
    peerX25519PKey, err := ecdh.X25519().NewPublicKey(encryptedPfsPublicKey[mlkemPubSize : mlkemPubSize+x25519KeySize])
    if err != nil {
        log.Printf("[SERVER-HANDSHAKE] parse peer X25519 key error: %v", err)
        return nil, fmt.Errorf("parse peer x25519 key: %w", err)
    }
    x25519SKey, err := ecdh.X25519().GenerateKey(rand.Reader)
    if err != nil {
        log.Printf("[SERVER-HANDSHAKE] generate X25519 key error: %v", err)
        return nil, fmt.Errorf("generate x25519 key: %w", err)
    }
    x25519Key, err := x25519SKey.ECDH(peerX25519PKey)
    if err != nil {
        log.Printf("[SERVER-HANDSHAKE] X25519 ECDH error: %v", err)
        return nil, fmt.Errorf("x25519 ECDH: %w", err)
    }
    pfsKey := make([]byte, x25519KeySize+x25519KeySize)
    copy(pfsKey, mlkem768Key)
    copy(pfsKey[x25519KeySize:], x25519Key)
    serverPfsPublicKey := append(encapsulatedPfsKey, x25519SKey.PublicKey().Bytes()...)
    unitedKey := append(pfsKey, nfsKey...)
    c.UnitedKey = unitedKey
    c.AEAD = NewAEAD(serverPfsPublicKey, unitedKey)
    clientPfsPublicKey := encryptedPfsPublicKey[:mlkemPubSize+x25519KeySize]
    c.PeerAEAD = NewAEAD(clientPfsPublicKey, unitedKey)
    ticket := [16]byte{}
    if _, err := rand.Read(ticket[:]); err != nil {
        log.Printf("[SERVER-HANDSHAKE] rand.Read ticket error: %v", err)
        return nil, fmt.Errorf("rand read ticket: %w", err)
    }
    seconds, err := randBetween(50, 60)
    if err != nil {
        log.Printf("randBetween failed: %v, using default 60s", err)
        seconds = 60
    }
    copy(ticket[:], EncodeLength(int(seconds)))
    expireTime := time.Now().Add(time.Duration(seconds) * time.Second)
    i.RWLock.Lock()
    i.Lasts[(time.Now().Unix()+60)/60+2] = ticket
    i.Tickets = append(i.Tickets, ticket)
    i.Sessions[ticket] = &ServerSession{PfsKey: pfsKey, Expire: expireTime, NfsKeys: sync.Map{}, NfsKeysCnt: 0}
    i.RWLock.Unlock()
    serverHello := make([]byte, mlkemCTSize+x25519KeySize+aeadOverhead+x25519KeySize)
    // 修正：使用 nil nonce 自动递增
    sealedPfs := nfsAEAD.Seal(nil, nil, serverPfsPublicKey, nil)
    copy(serverHello[:mlkemCTSize+x25519KeySize+aeadOverhead], sealedPfs)
    sealedTicket := c.AEAD.Seal(nil, nil, ticket[:], nil)
    copy(serverHello[mlkemCTSize+x25519KeySize+aeadOverhead:], sealedTicket)
    log.Printf("[SERVER-HANDSHAKE] serverHello len=%d, first64=%x", len(serverHello), serverHello[:64])
    if _, err := conn.Write(serverHello); err != nil {
        log.Printf("[SERVER-HANDSHAKE] write serverHello error: %v", err)
        return nil, fmt.Errorf("write server hello: %w", err)
    }
    log.Printf("[SERVER-HANDSHAKE] full handshake success")
    return c, nil
}

func NewServerConn(conn net.Conn, cfg *Config) (*FakeHTTPConn, error) {
    log.Printf("[SERVER-HTTP] NewServerConn start")
    fc := &FakeHTTPConn{
        RawConn:  NewRawConn(conn),
        host:     cfg.Host,
        isClient: false,
        chunkBuf: make([]byte, 0, 64*1024),
    }
    if err := fc.serverHandshake(); err != nil {
        log.Printf("[SERVER-HTTP] serverHandshake error: %v", err)
        return nil, err
    }
    log.Printf("[SERVER-HTTP] NewServerConn success")
    return fc, nil
}

func (c *FakeHTTPConn) serverHandshake() error {
    log.Printf("[SERVER-HTTP] serverHandshake entered")
    header, err := c.ReadUntilBlank()
    if err != nil {
        log.Printf("[SERVER-HTTP] ReadUntilBlank error: %v", err)
        return fmt.Errorf("read headers: %w", err)
    }
    log.Printf("[SERVER-HTTP] headers:\n%s", header)
    lines := strings.Split(header, "\r\n")
    if len(lines) == 0 || !strings.HasPrefix(lines[0], "GET ") {
        log.Printf("[SERVER-HTTP] not a GET request: %s", lines[0])
        return fmt.Errorf("not a GET request")
    }
    resp := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
    log.Printf("[SERVER-HTTP] sending response:\n%s", resp)
    if _, err := c.WriteString(resp); err != nil {
        log.Printf("[SERVER-HTTP] write response error: %v", err)
        return fmt.Errorf("write response: %w", err)
    }
    log.Printf("[SERVER-HTTP] serverHandshake complete")
    c.handshake = true
    return nil
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func main() {
    cfg, err := LoadConfig("server.json")
    if err != nil {
        log.Fatalf("load config: %v", err)
    }
    log.Printf("[SERVER-MAIN] config loaded: uuid=%s ip=%s port=%d", cfg.UUID, cfg.IP, cfg.Port)
    server := &ServerInstance{}
    if err := server.Init(cfg.Keys); err != nil {
        log.Fatalf("init server: %v", err)
    }
    log.Printf("[SERVER-MAIN] server initialized with %d keys", len(cfg.Keys))
    ln, err := net.Listen("tcp", cfg.IP+":"+strconv.Itoa(cfg.Port))
    if err != nil {
        log.Fatalf("listen: %v", err)
    }
    defer ln.Close()
    log.Printf("[SERVER-MAIN] Server listening on %s:%d", cfg.IP, cfg.Port)
    for {
        raw, err := ln.Accept()
        if err != nil {
            log.Printf("[SERVER-MAIN] accept error: %v", err)
            continue
        }
        go func(raw net.Conn) {
            defer raw.Close()
            log.Printf("[SERVER-MAIN] new connection from %s", raw.RemoteAddr())
            httpConn, err := NewServerConn(raw, cfg)
            if err != nil {
                log.Printf("[SERVER-MAIN] server HTTP error: %v", err)
                return
            }
            defer httpConn.Close()
            log.Printf("[SERVER-MAIN] after NewServerConn")
            sudokuConn, err := NewPackedTCPConn(httpConn, cfg.UUID)
            if err != nil {
                log.Printf("[SERVER-MAIN] packed tcp error: %v", err)
                return
            }
            log.Printf("[SERVER-MAIN] after NewPackedTCPConn")
            encConn, err := server.Handshake(sudokuConn)
            if err != nil {
                log.Printf("[SERVER-MAIN] handshake error: %v", err)
                return
            }
            log.Printf("[SERVER-MAIN] handshake complete")
            buf := make([]byte, 4096)
            n, err := encConn.Read(buf)
            if err == nil {
                encConn.Write(buf[:n])
            }
        }(raw)
    }
}