package main
import("bufio""bytes""crypto/cipher""crypto/rand""encoding/json""fmt""io""math/big""net""os""strconv""strings""sync""time""golang.org/x/crypto/chacha20""golang.org/x/crypto/chacha20poly1305""lukechampine.com/blake3")
type Config struct{UUID string`json:"uuid"`;IP string`json:"ip"`;Port int`json:"port"`;Host string`json:"host"`;UserAgent string`json:"user_agent"`;Keys[][]byte`json:"keys"`}
func LoadConfig(path string)(*Config,error){data,err:=os.ReadFile(path);if err!=nil{return nil,fmt.Errorf("read config: %w",err)};var cfg Config;if err:=json.Unmarshal(data,&cfg);err!=nil{return nil,fmt.Errorf("parse config: %w",err)};if cfg.UUID==""||cfg.IP==""||cfg.Port==0||cfg.Host==""||cfg.UserAgent==""||len(cfg.Keys)==0{return nil,fmt.Errorf("missing required field")};return&cfg,nil}
const maxHeaderSize=4096;const maxChunkSize=64*1024
type RawConn struct{net.Conn;reader*bufio.Reader}
func NewRawConn(conn net.Conn)*RawConn{return&RawConn{Conn:conn,reader:bufio.NewReader(conn)}}
func(r*RawConn)ReadLine()(string,error){line,err:=r.reader.ReadString('\n');if err!=nil{return"",err};return strings.TrimRight(line,"\r\n"),nil}
func(r*RawConn)ReadUntilBlank()(string,error){var sb strings.Builder;total:=0;for{line,err:=r.ReadLine();if err!=nil{return"",err};if line==""{break};total+=len(line)+2;if total>maxHeaderSize{return"",fmt.Errorf("header size exceeds limit %d",maxHeaderSize)};sb.WriteString(line);sb.WriteString("\r\n")};return sb.String(),nil}
func(r*RawConn)WriteString(s string)(int,error){return r.Conn.Write([]byte(s))}
func(r*RawConn)ReadFull(buf []byte)(int,error){return io.ReadFull(r.reader,buf)}
func(r*RawConn)Discard(n int)(int,error){return r.reader.Discard(n)}
func(r*RawConn)Buffered()int{return r.reader.Buffered()}
type FakeHTTPConn struct{*RawConn;host string;userAgent string;isClient bool;handshake bool;closed bool;writeMu sync.Mutex;readMu sync.Mutex;chunkBuf[]byte}
func(c*FakeHTTPConn)Write(p []byte)(int,error){if len(p)==0{return 0,nil};c.writeMu.Lock();defer c.writeMu.Unlock();if c.closed{return 0,net.ErrClosed};chunk:=fmt.Sprintf("%x\r\n%s\r\n",len(p),p);if _,err:=c.Conn.Write([]byte(chunk));err!=nil{return 0,err};return len(p),nil}
func(c*FakeHTTPConn)Read(p []byte)(int,error){if len(p)==0{return 0,nil};c.readMu.Lock();defer c.readMu.Unlock();if c.closed{return 0,net.ErrClosed};if len(c.chunkBuf)>0{n:=copy(p,c.chunkBuf);c.chunkBuf=c.chunkBuf[n:];return n,nil};line,err:=c.ReadLine();if err!=nil{return 0,err};if idx:=strings.Index(line,";");idx!=-1{line=line[:idx]};size,err:=strconv.ParseInt(strings.TrimSpace(line),16,64);if err!=nil{return 0,fmt.Errorf("invalid chunk size: %s",line)};if size==0{c.Discard(2);return 0,io.EOF};if size>maxChunkSize{return 0,fmt.Errorf("chunk size %d exceeds limit %d",size,maxChunkSize)};if size>int64(len(p)){buf:=make([]byte,size);if _,err:=c.ReadFull(buf);err!=nil{return 0,err};c.Discard(2);n:=copy(p,buf);c.chunkBuf=append(c.chunkBuf,buf[n:]...);return n,nil};if _,err:=c.ReadFull(p[:size]);err!=nil{return 0,err};c.Discard(2);return int(size),nil}
func(c*FakeHTTPConn)Close()error{c.writeMu.Lock();defer c.writeMu.Unlock();if c.closed{return nil};c.closed=true;c.Conn.Write([]byte("0\r\n\r\n"));return c.Conn.Close()}
var OutBytesPool=sync.Pool{New:func()interface{}{return make([]byte,5+8192+16)}}
type CommonConn struct{net.Conn;UnitedKey[]byte;AEAD*AEAD;PeerAEAD*AEAD;rawInput bytes.Buffer;input bytes.Reader}
func NewCommonConn(conn net.Conn)*CommonConn{return&CommonConn{Conn:conn}}
func(c*CommonConn)Write(b []byte)(int,error){if len(b)==0{return 0,nil};outBytes:=OutBytesPool.Get().([]byte);defer OutBytesPool.Put(outBytes);for n:=0;n<len(b);{chunk:=b[n:];if len(chunk)>8192{chunk=chunk[:8192]};n+=len(chunk);headerAndData:=outBytes[:5+len(chunk)+16];EncodeHeader(headerAndData,len(chunk)+16);max:=false;if bytes.Equal(c.AEAD.Nonce[:],MaxNonce){max=true};c.AEAD.Seal(headerAndData[:5],nil,chunk,headerAndData[:5]);if max{c.AEAD=NewAEAD(headerAndData,c.UnitedKey)};if _,err:=c.Conn.Write(headerAndData);err!=nil{return 0,err}};return len(b),nil}
func(c*CommonConn)Read(b []byte)(int,error){if len(b)==0{return 0,nil};if c.PeerAEAD==nil{serverRandom:=make([]byte,16);if _,err:=io.ReadFull(c.Conn,serverRandom);err!=nil{return 0,err};c.PeerAEAD=NewAEAD(serverRandom,c.UnitedKey)};if c.input.Len()>0{return c.input.Read(b)};peerHeader:=[5]byte{};if _,err:=io.ReadFull(c.Conn,peerHeader[:]);err!=nil{return 0,err};l,err:=DecodeHeader(peerHeader[:]);if err!=nil{return 0,err};if c.rawInput.Cap()<l{c.rawInput.Grow(l)};peerData:=c.rawInput.Bytes()[:l];if _,err:=io.ReadFull(c.Conn,peerData);err!=nil{return 0,err};dst:=peerData[:l-16];if len(dst)<=len(b){dst=b[:len(dst)]};var newAEAD*AEAD;if bytes.Equal(c.PeerAEAD.Nonce[:],MaxNonce){newAEAD=NewAEAD(append(peerHeader[:],peerData...),c.UnitedKey)};_,err=c.PeerAEAD.Open(dst[:0],nil,peerData,peerHeader[:]);if newAEAD!=nil{c.PeerAEAD=newAEAD};if err!=nil{return 0,err};if len(dst)>len(b){c.input.Reset(dst[copy(b,dst):]);dst=b};return len(dst),nil}
type AEAD struct{chacha20poly1305.XChaCha20Poly1305;Nonce[24]byte}
func NewAEAD(ctx,key []byte)*AEAD{k:=make([]byte,32);blake3.DeriveKey(k,string(ctx),key);aead,_:=chacha20poly1305.NewX(k);return&AEAD{XChaCha20Poly1305:*aead}}
func(a*AEAD)Seal(dst,nonce,plaintext,additionalData []byte)[]byte{if nonce==nil{nonce=IncreaseNonce(a.Nonce[:])};return a.XChaCha20Poly1305.Seal(dst,nonce,plaintext,additionalData)}
func(a*AEAD)Open(dst,nonce,ciphertext,additionalData []byte)([]byte,error){if nonce==nil{nonce=IncreaseNonce(a.Nonce[:])};return a.XChaCha20Poly1305.Open(dst,nonce,ciphertext,additionalData)}
func IncreaseNonce(nonce []byte)[]byte{for i:=range 24{nonce[23-i]++;if nonce[23-i]!=0{break}};return nonce}
var MaxNonce=bytes.Repeat([]byte{255},24)
func EncodeLength(l int)[]byte{return[]byte{byte(l>>8),byte(l)}}
func DecodeLength(b []byte)int{return int(b[0])<<8|int(b[1])}
func EncodeHeader(h []byte,l int){h[0]=23;h[1]=3;h[2]=3;h[3]=byte(l>>8);h[4]=byte(l)}
func DecodeHeader(h []byte)(l int,err error){l=int(h[3])<<8|int(h[4]);if h[0]!=23||h[1]!=3||h[2]!=3{l=0};if l<17||l>16640{err=fmt.Errorf("invalid header: %v",h[:5])};return}
func randBetween(min,max int64)int64{if min==max{return min};n,_:=rand.Int(rand.Reader,big.NewInt(max-min+1));return min+n.Int64()}
func NewCTR(key,iv []byte)cipher.Stream{k:=make([]byte,32);blake3.DeriveKey(k,"VLESS",key);nonce:=make([]byte,12);blake3.DeriveKey(nonce,"CTR-NONCE",append(key,iv...));c,_:=chacha20.NewUnauthenticatedCipher(k,nonce);return c}