package socks5

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

func RunServer(serverAddr string, udpserverAddr string) {
	listener, err := net.Listen("tcp", serverAddr)
	if err != nil {
		log.Fatal(err)
	}
	Log.Info("Start server on ", listener.Addr())
	defer listener.Close()
	udpListenAddr, err := net.ResolveUDPAddr("udp", udpserverAddr)
	if err != nil {
		log.Fatal(err)
	}

	go runUDPRelayServer(udpListenAddr, 150*time.Second)

	for {
		conn, err := listener.Accept()
		if err != nil {
			Log.Error(err)
			continue
		}
		go handleServerConnection(conn, udpListenAddr)
	}
}

func handleServerConnection(conn net.Conn, udpListenAddr *net.UDPAddr) {
	// Log.Debug("New connection from ", conn.RemoteAddr())
	defer conn.Close()

	if !Negotiate(conn) {
		Log.Error("Failed to negotiate with client")
		return
	}

	// 解析请求的目标地址和端口
	cmd, addr, port, err := GetRequest(conn)
	if err != nil {
		Log.Error(err)
		return
	}
	if cmd == 0x01 {
		// TCP

		targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", addr, port))
		if err != nil {
			Log.Error(err)
			return
		}
		defer targetConn.Close()

		Log.Info("[TCP] ", conn.RemoteAddr(), " -> ", addr, ":", port)

		SendReply(conn, 0, targetConn.RemoteAddr().(*net.TCPAddr).IP.String(), targetConn.RemoteAddr().(*net.TCPAddr).Port)

		// 数据转发
		go io.Copy(targetConn, conn)
		io.Copy(conn, targetConn)
	} else if cmd == 0x03 {
		// UDP
		Log.Info("[UDP ASSOCIATE] ", conn.RemoteAddr())
		SendReply(conn, 0, udpListenAddr.IP.String(), udpListenAddr.Port)
	}
}
