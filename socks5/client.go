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
	targetAddress, targetPort, err := GetRequest(conn)
	if err != nil {
		Log.Error(err)
		return
	}
	err = SendRequest(ProxyConn, 0x01, targetAddress, targetPort)
	if err != nil {
		Log.Error(err)
		return
	}

	// FORWARD REPLY
	rep, bindaddr, bindport, err := GetReply(ProxyConn)
	if err != nil {
		Log.Error(err)
		return
	}
	SendReply(conn, rep, bindaddr, bindport)
	if rep != 0x00 {
		Log.Error("Failed to connect to target")
		return
	}
	Log.Info("Target: ", targetAddress, ":", targetPort)

	// FORWARD DATA
	go io.Copy(ProxyConn, conn)
	io.Copy(conn, ProxyConn)
}
