package socks5

import (
	"fmt"
	"io"
	"log"
	"net"
)

func RunServer(serverAddr string) {
	listener, err := net.Listen("tcp", serverAddr)
	if err != nil {
		log.Fatal(err)
	}
	Log.Info("Start server on ", serverAddr)
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			Log.Error(err)
			continue
		}
		go handleServerConnection(conn)
	}
}

func handleServerConnection(conn net.Conn) {
	defer conn.Close()

	if !Negotiate(conn) {
		Log.Error("Failed to negotiate with client")
		return
	}

	// 解析请求的目标地址和端口
	targetAddress, targetPort, err := GetRequest(conn)
	if err != nil {
		Log.Error(err)
		return
	}

	// 建立到目标服务器的连接
	targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetAddress, targetPort))
	if err != nil {
		Log.Error(err)
		return
	}
	defer targetConn.Close()

	Log.Info("Connected to Target:", targetAddress, ":", targetPort)

	SendReply(conn, 0, targetConn.RemoteAddr().(*net.TCPAddr).IP.String(), targetConn.RemoteAddr().(*net.TCPAddr).Port)

	// 数据转发
	go io.Copy(targetConn, conn)
	io.Copy(conn, targetConn)
}
