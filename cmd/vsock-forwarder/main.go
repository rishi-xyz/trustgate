// vsock-forwarder runs on the (untrusted) parent instance and relays TCP
// connections to a service inside the enclave over vsock. It sees only what
// crosses the wire; confidentiality of application data must not depend on it.
package main

import (
	"flag"
	"io"
	"log"
	"net"
	"sync"

	"github.com/mdlayher/vsock"
)

func main() {
	listen := flag.String("listen", ":8443", "TCP listen address on the parent")
	cid := flag.Uint("cid", 16, "enclave CID (nitro-cli run-enclave --enclave-cid)")
	port := flag.Uint("port", 8080, "enclave vsock port")
	flag.Parse()

	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("forwarding %s -> vsock cid=%d port=%d", *listen, *cid, *port)
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go relay(c, uint32(*cid), uint32(*port))
	}
}

func relay(c net.Conn, cid, port uint32) {
	defer c.Close()
	v, err := vsock.Dial(cid, port, nil)
	if err != nil {
		log.Printf("dial enclave: %v", err)
		return
	}
	defer v.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	go cp(v, c)
	go cp(c, v)
	wg.Wait()
}
