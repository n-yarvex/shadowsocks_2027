package main
import("bufio""crypto/sha256""encoding/binary""fmt""io""net""sync")
const ioBufferSize=32*1024
type asciiLayout struct{}
func(*asciiLayout)isData(b byte)bool{return b>=0x21&&b<=0x60}
func(*asciiLayout)decodeChar(b byte)(byte,error){if b<0x21||b>0x60{return 0,fmt.Errorf("invalid char %d",b)};return b-0x21,nil}
func(*asciiLayout)encodeChar(v byte)byte{return v+0x21}
var encodePool=sync.Pool{New:func()interface{}{b:=make([]byte,0,8192);return&b}}
type packedEncoder struct{layout*asciiLayout;password string;table[64]byte;tableInit bool;mu sync.Mutex}
func newPackedEncoder(password string)*packedEncoder{return&packedEncoder{password:password}}
func(e*packedEncoder)initTable(){if e.tableInit{return};hash:=sha256.Sum256([]byte(e.password));seed:=int64(binary.BigEndian.Uint64(hash[:8]));rng:=newSeededRand(seed);perm:=rng.Perm(64);for i,v:=range perm{e.table[i]=byte(v)};e.tableInit=true}
func(e*packedEncoder)encode(p []byte)([]byte,error){if len(p)==0{return nil,nil};e.mu.Lock();defer e.mu.Unlock();e.initTable();bufPtr:=encodePool.Get().(*[]byte);buf:=*bufPtr;buf=buf[:0];if cap(buf)<len(p)*2+8{buf=make([]byte,0,len(p)*2+8)};var bitBuf uint64;var bitCount uint8;for _,b:=range p{bitBuf=(bitBuf<<8)|uint64(b);bitCount+=8;for bitCount>=6{bitCount-=6;group:=byte(bitBuf>>bitCount);enc:=e.table[group&0x3f];buf=append(buf,e.layout.encodeChar(enc));if bitCount>0{bitBuf&=(uint64(1)<<bitCount)-1}else{bitBuf=0}}};if bitCount>0{group:=byte(bitBuf<<(6-bitCount));enc:=e.table[group&0x3f];buf=append(buf,e.layout.encodeChar(enc))};out:=make([]byte,len(buf));copy(out,buf);*bufPtr=buf[:0];encodePool.Put(bufPtr);return out,nil}
type packedDecoder struct{layout*asciiLayout;password string;inverse[64]byte;tableInit bool;bitBuf uint64;bitCount int;mu sync.Mutex}
func newPackedDecoder(password string)*packedDecoder{return&packedDecoder{password:password}}
func(d*packedDecoder)initTable(){if d.tableInit{return};hash:=sha256.Sum256([]byte(d.password));seed:=int64(binary.BigEndian.Uint64(hash[:8]));rng:=newSeededRand(seed);perm:=rng.Perm(64);for i,v:=range perm{d.inverse[v]=byte(i)};d.tableInit=true}
func(d*packedDecoder)decodeChunk(in []byte,pending []byte)([]byte,error){d.mu.Lock();defer d.mu.Unlock();d.initTable();for _,b:=range in{if!d.layout.isData(b){continue};v,err:=d.layout.decodeChar(b);if err!=nil{d.bitBuf=0;d.bitCount=0;return pending,err};orig:=d.inverse[v];d.bitBuf=(d.bitBuf<<6)|uint64(orig);d.bitCount+=6;for d.bitCount>=8{d.bitCount-=8;pending=append(pending,byte(d.bitBuf>>d.bitCount));if d.bitCount>0{d.bitBuf&=(uint64(1)<<d.bitCount)-1}else{d.bitBuf=0}}};return pending,nil}
func(d*packedDecoder)reset()error{err:=error(nil);if d.bitCount>0{err=fmt.Errorf("trailing bits discarded")};d.bitBuf=0;d.bitCount=0;return err}
type streamReader struct{reader*bufio.Reader;rawBuf[]byte;pending[]byte;decode*packedDecoder;mu sync.Mutex}
func newStreamReader(conn net.Conn,decoder*packedDecoder)io.Reader{return&streamReader{reader:bufio.NewReaderSize(conn,ioBufferSize),rawBuf:make([]byte,ioBufferSize),pending:make([]byte,0,4096),decode:decoder}}
func(r*streamReader)Read(p []byte)(int,error){r.mu.Lock();defer r.mu.Unlock();if len(r.pending)>0{n:=copy(p,r.pending);r.pending=r.pending[n:];return n,nil};for{nr,err:=r.reader.Read(r.rawBuf);if nr>0{var dErr error;r.pending,dErr=r.decode.decodeChunk(r.rawBuf[:nr],r.pending[:0]);if dErr!=nil{r.decode.reset();r.pending=r.pending[:0];return 0,dErr}};if err!=nil{if err==io.EOF{_=r.decode.reset();if len(r.pending)>0{break}};return 0,err};if len(r.pending)>0{break}};n:=copy(p,r.pending);r.pending=r.pending[n:];return n,nil}
type streamWriter struct{conn net.Conn;encode*packedEncoder;mu sync.Mutex}
func newStreamWriter(conn net.Conn,encoder*packedEncoder)io.Writer{return&streamWriter{conn:conn,encode:encoder}}
func(w*streamWriter)Write(p []byte)(int,error){if len(p)==0{return 0,nil};w.mu.Lock();defer w.mu.Unlock();encoded,err:=w.encode.encode(p);if err!=nil{return 0,err};if _,err:=w.conn.Write(encoded);err!=nil{return 0,err};return len(p),nil}
type wrappedConn struct{net.Conn;reader io.Reader;writer io.Writer}
func(c*wrappedConn)Read(p []byte)(int,error){return c.reader.Read(p)}
func(c*wrappedConn)Write(p []byte)(int,error){return c.writer.Write(p)}
func NewPackedTCPConn(conn net.Conn,password string)(net.Conn,error){if password==""{return nil,fmt.Errorf("password required")};decoder:=newPackedDecoder(password);encoder:=newPackedEncoder(password);reader:=newStreamReader(conn,decoder);writer:=newStreamWriter(conn,encoder);return&wrappedConn{Conn:conn,reader:reader,writer:writer},nil}
type seededRand struct{mu sync.Mutex;seed int64}
func newSeededRand(seed int64)*seededRand{return&seededRand{seed:seed}}
func(r*seededRand)Perm(n int)[]int{r.mu.Lock();defer r.mu.Unlock();rand:=func()int64{r.seed=(r.seed*1103515245+12345)&0x7fffffff;return r.seed};arr:=make([]int,n);for i:=0;i<n;i++{arr[i]=i};for i:=n-1;i>0;i--{j:=int(rand()%int64(i+1));arr[i],arr[j]=arr[j],arr[i]};return arr}