package main

import (
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
    log.Printf("[CLIENT-INIT] start")
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
                log.Printf("[CLIENT-INIT] parse X25519 key error: %v", err)
                return err
            }
            i.NfsPKeys[j] = pub
            i.RelaysLength += x25519KeySize + x25519KeySize
            log.Printf("[CLIENT-INIT] key %d is X25519 public", j)
        } else {
            var ek *mlkem.EncapsulationKey768
            ek, err = mlkem.NewEncapsulationKey768(k)
            if err != nil {
                log.Printf("[CLIENT-INIT] parse ML-KEM key error: %v", err)
                return err
            }
            i.NfsPKeys[j] = ek
            i.RelaysLength += mlkemCTSize + x25519KeySize
            log.Printf("[CLIENT-INIT] key %d is ML-KEM public", j)
        }
        i.Hash32s[j] = blake3.Sum256(k)
    }
    i.RelaysLength -= x25519KeySize
    log.Printf("[CLIENT-INIT] relaysLength=%d", i.RelaysLength)
    return nil
}

func (i *ClientInstance) Handshake(conn net.Conn) (*CommonConn, error) {
    log.Printf("[CLIENT-HANDSHAKE] start")
    if i.NfsPKeys == nil {
        log.Printf("[CLIENT-HANDSHAKE] NfsPKeys nil")
        return nil, fmt.Errorf("uninitialized")
    }
    c := NewCommonConn(conn)
    iv := make([]byte, 16)
    if _, err := rand.Read(iv); err != nil {
        log.Printf("[CLIENT-HANDSHAKE] rand.Read iv error: %v", err)
        return nil, fmt.Errorf("rand read iv: %w", err)
    }
    log.Printf("[CLIENT-HANDSHAKE] iv: %x", iv)
    relaysTotal := 16 + i.RelaysLength
    relaysBuf := make([]byte, i.RelaysLength)
    relays := relaysBuf
    var nfsKey []byte
    var lastCTR cipher.Stream
    log.Printf("[CLIENT-HANDSHAKE] relaysTotal=%d", relaysTotal)
    for j, k := range i.NfsPKeys {
        log.Printf("[CLIENT-HANDSHAKE] processing relay %d", j)
        index := x25519KeySize
        if pub, ok := k.(*ecdh.PublicKey); ok {
            log.Printf("[CLIENT-HANDSHAKE] relay %d X25519", j)
            privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
            if err != nil {
                log.Printf("[CLIENT-HANDSHAKE] generate X25519 key error: %v", err)
                return nil, fmt.Errorf("generate x25519 key: %w", err)
            }
            copy(relays, privateKey.PublicKey().Bytes())
            nfsKey, err = privateKey.ECDH(pub)
            if err != nil {
                log.Printf("[CLIENT-HANDSHAKE] X25519 ECDH error: %v", err)
                return nil, fmt.Errorf("x25519 ECDH: %w", err)
            }
        } else if ek, ok := k.(*mlkem.EncapsulationKey768); ok {
            log.Printf("[CLIENT-HANDSHAKE] relay %d ML-KEM", j)
            ct, err := ek.Encapsulate()
            if err != nil {
                log.Printf("[CLIENT-HANDSHAKE] ML-KEM encapsulate error: %v", err)
                return nil, fmt.Errorf("mlkem encapsulate: %w", err)
            }
            copy(relays, ct)
            index = mlkemCTSize
        }
        if lastCTR != nil {
            lastCTR.XORKeyStream(relays, relays[:x25519KeySize])
        }
        if j == len(i.NfsPKeys)-1 {
            break
        }
        lastCTR = NewCTR(nfsKey, iv)
        lastCTR.XORKeyStream(relays[index:], i.Hash32s[j+1][:])
        relays = relays[index+x25519KeySize:]
    }
    log.Printf("[CLIENT-HANDSHAKE] nfsKey: %x", nfsKey)
    nfsAEAD := NewAEAD(iv, nfsKey)
    i.RWLock.RLock()
    ticket := i.Ticket
    expire := i.Expire
    pfsKey := i.PfsKey
    i.RWLock.RUnlock()
    if ticket != nil && time.Now().Before(expire) {
        log.Printf("[CLIENT-HANDSHAKE] using 0-RTT ticket len=%d", len(ticket))
        unitedKey := append(pfsKey, nfsKey...)
        c.UnitedKey = unitedKey
        clientHello := make([]byte, relaysTotal+18+x25519KeySize)
        copy(clientHello, iv)
        copy(clientHello[16:relaysTotal], relaysBuf)
        log.Printf("[CLIENT-HANDSHAKE] clientHello before seal: %x", clientHello)
        sealedLen := nfsAEAD.Seal(nil, nil, EncodeLength(x25519KeySize), nil)
        copy(clientHello[relaysTotal:relaysTotal+18], sealedLen)
        sealedTicket := nfsAEAD.Seal(nil, nil, ticket, nil)
        copy(clientHello[relaysTotal+18:relaysTotal+18+x25519KeySize], sealedTicket)
        log.Printf("[CLIENT-HANDSHAKE] clientHello after seal: %x", clientHello)
        if _, err := conn.Write(clientHello); err != nil {
            log.Printf("[CLIENT-HANDSHAKE] write error: %v", err)
            return nil, fmt.Errorf("write client hello: %w", err)
        }
        c.AEAD = NewAEAD(clientHello[relaysTotal+18:relaysTotal+18+x25519KeySize], unitedKey)
        log.Printf("[CLIENT-HANDSHAKE] 0-RTT success")
        return c, nil
    }
    log.Printf("[CLIENT-HANDSHAKE] full handshake")
    clientHello := make([]byte, relaysTotal+18+mlkemPubSize+x25519KeySize+aeadOverhead)
    copy(clientHello, iv)
    copy(clientHello[16:relaysTotal], relaysBuf)
    pfsKeyExchangeLength := 18 + mlkemPubSize + x25519KeySize + aeadOverhead
    sealedLen := nfsAEAD.Seal(nil, nil, EncodeLength(pfsKeyExchangeLength-18), nil)
    copy(clientHello[relaysTotal:relaysTotal+18], sealedLen)
    log.Printf("[CLIENT-HANDSHAKE] sealed length field: %x", clientHello[relaysTotal:relaysTotal+18])
    mlkemDKey, err := mlkem.GenerateKey768()
    if err != nil {
        log.Printf("[CLIENT-HANDSHAKE] generate ML-KEM key error: %v", err)
        return nil, fmt.Errorf("generate mlkem key: %w", err)
    }
    x25519SKey, err := ecdh.X25519().GenerateKey(rand.Reader)
    if err != nil {
        log.Printf("[CLIENT-HANDSHAKE] generate X25519 key error: %v", err)
        return nil, fmt.Errorf("generate x25519 key: %w", err)
    }
    clientPfsPublicKey := append(mlkemDKey.EncapsulationKey().Bytes(), x25519SKey.PublicKey().Bytes()...)
    log.Printf("[CLIENT-HANDSHAKE] clientPfsPublicKey: %x", clientPfsPublicKey)
    // 修正：使用 MaxNonce 加密 PFS 公钥
    sealedPfs := nfsAEAD.Seal(nil, MaxNonce, clientPfsPublicKey, nil)
    copy(clientHello[relaysTotal+18:relaysTotal+18+mlkemPubSize+x25519KeySize], sealedPfs)
    log.Printf("[CLIENT-HANDSHAKE] sealed PFS key: %x", clientHello[relaysTotal+18:relaysTotal+18+mlkemPubSize+x25519KeySize])
    log.Printf("[CLIENT-HANDSHAKE] full clientHello len=%d, first64=%x", len(clientHello), clientHello[:64])
    if _, err := conn.Write(clientHello); err != nil {
        log.Printf("[CLIENT-HANDSHAKE] write clientHello error: %v", err)
        return nil, fmt.Errorf("write client hello: %w", err)
    }
    encryptedPfsPublicKey := make([]byte, mlkemCTSize+x25519KeySize+aeadOverhead)
    if _, err := io.ReadFull(conn, encryptedPfsPublicKey); err != nil {
        log.Printf("[CLIENT-HANDSHAKE] read server PFS key error: %v", err)
        return nil, fmt.Errorf("read server pfs public key: %w", err)
    }
    log.Printf("[CLIENT-HANDSHAKE] received encryptedPfsPublicKey: %x", encryptedPfsPublicKey)
    if _, err := nfsAEAD.Open(encryptedPfsPublicKey[:0], MaxNonce, encryptedPfsPublicKey, nil); err != nil {
        log.Printf("[CLIENT-HANDSHAKE] decrypt PFS key error: %v", err)
        return nil, fmt.Errorf("decrypt server pfs public key: %w", err)
    }
    log.Printf("[CLIENT-HANDSHAKE] decrypted PFS key: %x", encryptedPfsPublicKey[:mlkemCTSize+x25519KeySize])
    mlkem768Key, err := mlkemDKey.Decapsulate(encryptedPfsPublicKey[:mlkemCTSize])
    if err != nil {
        log.Printf("[CLIENT-HANDSHAKE] ML-KEM decapsulate error: %v", err)
        return nil, fmt.Errorf("mlkem decapsulate: %w", err)
    }
    peerX25519PKey, err := ecdh.X25519().NewPublicKey(encryptedPfsPublicKey[mlkemCTSize : mlkemCTSize+x25519KeySize])
    if err != nil {
        log.Printf("[CLIENT-HANDSHAKE] parse peer X25519 key error: %v", err)
        return nil, fmt.Errorf("parse peer x25519 key: %w", err)
    }
    x25519Key, err := x25519SKey.ECDH(peerX25519PKey)
    if err != nil {
        log.Printf("[CLIENT-HANDSHAKE] X25519 ECDH error: %v", err)
        return nil, fmt.Errorf("x25519 ECDH: %w", err)
    }
    pfsKey = make([]byte, x25519KeySize+x25519KeySize)
    copy(pfsKey, mlkem768Key)
    copy(pfsKey[x25519KeySize:], x25519Key)
    unitedKey := append(pfsKey, nfsKey...)
    c.UnitedKey = unitedKey
    c.AEAD = NewAEAD(clientPfsPublicKey, unitedKey)
    serverPfsPublicKey := encryptedPfsPublicKey[:mlkemCTSize+x25519KeySize]
    c.PeerAEAD = NewAEAD(serverPfsPublicKey, unitedKey)
    encryptedTicket := make([]byte, x25519KeySize)
    if _, err := io.ReadFull(conn, encryptedTicket); err != nil {
        log.Printf("[CLIENT-HANDSHAKE] read ticket error: %v", err)
        return nil, fmt.Errorf("read ticket: %w", err)
    }
    log.Printf("[CLIENT-HANDSHAKE] encryptedTicket: %x", encryptedTicket)
    ticket, err = c.PeerAEAD.Open(nil, nil, encryptedTicket, nil)
    if err != nil {
        log.Printf("[CLIENT-HANDSHAKE] decrypt ticket error: %v", err)
        return nil, fmt.Errorf("decrypt ticket: %w", err)
    }
    log.Printf("[CLIENT-HANDSHAKE] decrypted ticket: %x", ticket)
    seconds := DecodeLength(ticket)
    log.Printf("[CLIENT-HANDSHAKE] ticket seconds=%d", seconds)
    if seconds > 0 {
        i.RWLock.Lock()
        i.Expire = time.Now().Add(time.Duration(seconds) * time.Second)
        i.PfsKey = pfsKey
        i.Ticket = ticket[:16]
        i.RWLock.Unlock()
    }
    log.Printf("[CLIENT-HANDSHAKE] full handshake success")
    return c, nil
}

func NewClientConn(conn net.Conn, cfg *Config) (*FakeHTTPConn, error) {
    log.Printf("[CLIENT-HTTP] NewClientConn start")
    fc := &FakeHTTPConn{
        RawConn:   NewRawConn(conn),
        host:      cfg.Host,
        userAgent: cfg.UserAgent,
        isClient:  true,
        chunkBuf:  make([]byte, 0, 64*1024),
    }
    if err := fc.clientHandshake(); err != nil {
        log.Printf("[CLIENT-HTTP] clientHandshake error: %v", err)
        return nil, err
    }
    log.Printf("[CLIENT-HTTP] NewClientConn success")
    return fc, nil
}

func (c *FakeHTTPConn) clientHandshake() error {
    log.Printf("[CLIENT-HTTP] clientHandshake entered")
    req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n", c.host, c.userAgent)
    log.Printf("[CLIENT-HTTP] sending request: %q", req)
    if _, err := c.WriteString(req); err != nil {
        log.Printf("[CLIENT-HTTP] write request error: %v", err)
        return fmt.Errorf("write request: %w", err)
    }
    status, err := c.ReadLine()
    if err != nil {
        log.Printf("[CLIENT-HTTP] read status error: %v", err)
        return fmt.Errorf("read status: %w", err)
    }
    log.Printf("[CLIENT-HTTP] received status: %s", status)
    if !strings.Contains(status, "200 OK") {
        return fmt.Errorf("unexpected server response: %s", status)
    }
    for {
        line, err := c.ReadLine()
        if err != nil {
            return fmt.Errorf("read headers: %w", err)
        }
        if line == "" {
            break
        }
        log.Printf("[CLIENT-HTTP] header: %s", line)
    }
    log.Printf("[CLIENT-HTTP] clientHandshake complete")
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
    cfg, err := LoadConfig("client.json")
    if err != nil {
        log.Fatalf("load config: %v", err)
    }
    log.Printf("[CLIENT-MAIN] config loaded: uuid=%s ip=%s port=%d", cfg.UUID, cfg.IP, cfg.Port)
    client := &ClientInstance{}
    if err := client.Init(cfg.Keys); err != nil {
        log.Fatalf("init client: %v", err)
    }
    log.Printf("[CLIENT-MAIN] client initialized with %d keys", len(cfg.Keys))
    raw, err := net.Dial("tcp", cfg.IP+":"+strconv.Itoa(cfg.Port))
    if err != nil {
        log.Fatalf("dial: %v", err)
    }
    defer raw.Close()
    log.Printf("[CLIENT-MAIN] connected to %s", raw.RemoteAddr())
    httpConn, err := NewClientConn(raw, cfg)
    if err != nil {
        log.Fatalf("http client: %v", err)
    }
    defer httpConn.Close()
    log.Printf("[CLIENT-MAIN] HTTP handshake done")
    sudokuConn, err := NewPackedTCPConn(httpConn, cfg.UUID)
    if err != nil {
        log.Fatalf("packed tcp: %v", err)
    }
    log.Printf("[CLIENT-MAIN] packed tcp created")
    encConn, err := client.Handshake(sudokuConn)
    if err != nil {
        log.Fatalf("handshake: %v", err)
    }
    log.Printf("[CLIENT-MAIN] handshake success")
    encConn.Write([]byte("Hello, server!"))
    buf := make([]byte, 1024)
    n, err := encConn.Read(buf)
    if err == nil {
        fmt.Println("Received:", string(buf[:n]))
    }
}