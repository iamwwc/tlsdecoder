package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

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
	ln := Must2(net.Listen("tcp4",":3000")).(net.Listener)
	Must(http.ServeTLS(ln, Decoder{},"",""))
	defer Must(ln.Close())
}

type Decoder struct {}
func (f Decoder)ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		f.handleHTTPTunneling(w,r)
		return
	}
}

func (f Decoder) handleHTTPTunneling(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp",r.Host,10 * time.Second)
	if err != nil {
		log(err)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log(err)
		return
	}
	srcConn, _, err := hijacker.Hijack()
	if err != nil {
		log(err)
		return
	}
	go transfer(destConn, srcConn)
	go transfer(srcConn, destConn)
}

func transfer(conn1 net.Conn, conn2 net.Conn)  {
	defer conn1.Close()
	defer conn2.Close()
	io.Copy(conn1,conn2)
}

func log(err error) {
	fmt.Errorf("%v\n",err)
}