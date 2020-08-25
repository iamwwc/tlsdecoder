package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
)

var pair = Must2(tls.LoadX509KeyPair("rootCa.cert", "rootCa.key")).(tls.Certificate)
var rootTemplate,err = x509.ParseCertificate(pair.Certificate[0])
func Must2(any interface{}, err error) interface{} {
	Must(err)
	return any
}

func Must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	http.ListenAndServe("localhost:3000", Decoder{})
}

type Decoder struct{}

func (f Decoder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		w.WriteHeader(200)
		f.handleHTTPConnect(w, r)
		return
	}
	// TODO 下面处理裸HTTP
}

func (f Decoder) handleHTTPConnect(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log(errors.New("not ok"))
		return
	}
	srcConn, _, err := hijacker.Hijack()
	if err != nil {
		log(err)
		return
	}
	NewAdaptor(srcConn, w, r).decryptTLS()
}

func transfer(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func log(err error) {
	fmt.Errorf("%v\n", err)
}

type TLSAdaptor struct {
	srcRequestURI    string
	selfSignCertPair tls.Certificate
	isHttp           bool
	srcConn          *tls.Conn
	template         tls.Certificate
	reader           *ConnReader
}

func (t *TLSAdaptor) createCertForName(name string) {

}

func (t *TLSAdaptor) decryptTLS() {

	dstConn, err := tls.Dial("tcp", t.srcRequestURI, &tls.Config{})
	if err != nil {
		fmt.Errorf("%v\n", err)
		return
	}
	go func() {
		dstConn.Handshake()
		transfer(t.srcConn, dstConn)
	}()
	c := make(chan *Message, 1)
	go func() {
		t.srcConn.Handshake()
		for {
			bytes := make([]byte, 1024)
			n, err := t.srcConn.Read(bytes)
			c <- &Message{
				bytes: bytes,
				n:     n,
				err:   err,
			}
			dstConn.Write(bytes)
		}
	}()

	go func() {
		reader := ConnReader{
			conn:    t.srcConn,
			channel: c,
		}
		for {
			req, err := http.ReadRequest(bufio.NewReader(reader))
			if err != nil {
				log(err)
				return
			}
			fmt.Printf("成功解析到Https请求。Host： %s， Path %s\n", req.Host, req.URL)
		}
	}()
}

func NewAdaptor(conn net.Conn, w http.ResponseWriter, r *http.Request) *TLSAdaptor {
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{pair},
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			rootkey,_ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			b, err := x509.CreateCertificate(rand.Reader,pair.Leaf,pair.Leaf, rootkey.Public(),rootkey)
			if err != nil {
				panic(err)
			}
			cert, err := x509.ParseCertificate(b)
			tlsCert := &tls.Certificate{
				Certificate:                 [][]byte{cert.Raw},
				PrivateKey:                  rootkey,
				OCSPStaple:                  nil,
				SignedCertificateTimestamps: nil,
				Leaf:                        cert,
			}
			return tlsCert, nil
		},
	})
	return &TLSAdaptor{
		srcConn: tlsConn,
		srcRequestURI:    r.RequestURI,
		selfSignCertPair: pair,
		template: pair,
	}
}

type Message struct {
	bytes []byte
	n     int
	err   error
}

type ConnReader struct {
	conn    *tls.Conn
	channel chan *Message
}

// Read每次读取的数据都会写入 dest socket
// 我们将 byte stream 解析成 Request 是为了方便打印请求体
func (reader ConnReader) Read(bytes []byte) (int, error) {
	message := <-reader.channel
	copy(bytes, message.bytes)
	return message.n, message.err
}

func (reader ConnReader) Close() error {
	return reader.conn.Close()
}
func (reader ConnReader) Write(bytes []byte) (int, error) {
	return reader.conn.Write(bytes)
}
