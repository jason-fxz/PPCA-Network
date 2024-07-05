package socks5

import (
	"io"
	"log"
	"net"
)

func Client(ListenAddr string, proxyAddr string) {
	listener, err := net.Listen("tcp", ListenAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	Log.Info("proxyAddr: ", proxyAddr)
	Log.Info("Listening on ", ListenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleClientConnection(conn, proxyAddr)
	}
}

func handleClientConnection(conn net.Conn, proxyAddr string) {
	defer conn.Close()

	if !Negotiate(conn) {
		Log.Error("Failed to negotiate with client")
		return
	}

	// 建立到代理服务器的连接
	ProxyConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		Log.Error(err)
		return
	}
	if !TryNegotiate(ProxyConn) {
		Log.Error("Failed to negotiate with Proxy Server")
		return
	}
	defer ProxyConn.Close()

	// FORWARD REQUEST
	request := make([]byte, 256)
	n, err := conn.Read(request)
	if err != nil {
		Log.Error(err)
		return
	}
	_, err = ProxyConn.Write(request[:n])
	if err != nil {
		Log.Error(err)
		return
	}

	// FORWARD REPLY
	reply := make([]byte, 256)
	n, err = ProxyConn.Read(reply)
	if err != nil {
		Log.Error(err)
		return
	}
	conn.Write(reply[:n])
	if reply[1] != 0x00 {
		return
	}
	targetAddress, targetPort, err := ParseRequest(request[:n])
	if err != nil {
		Log.Error(err)
		return
	}
	Log.Info("Target: ", targetAddress, ":", targetPort)

	// FORWARD DATA
	go io.Copy(ProxyConn, conn)
	io.Copy(conn, ProxyConn)
}
