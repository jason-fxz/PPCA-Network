// Description: 代理客户端 - 规则匹配 by target address
package socks5

import (
	"fmt"
	"io"
	"net"
)

func ClientWithRule(listenAddr string, proxyAddr string, rulefile string) {
	InitHostRules(rulefile)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		Log.Fatal(err)
	}
	defer listener.Close()

	Log.Info("Listening on ", listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			Log.Warn(err)
			continue
		}
		// 处理每个连接
		go handleClientRuleConnection(conn, proxyAddr)
	}
}

func handleClientRuleConnection(conn net.Conn, proxyAddr string) {
	defer conn.Close()

	if !Negotiate(conn) {
		Log.Error("Failed to negotiate with client")
		return
	}

	// GET REQUEST
	request := make([]byte, 256)
	n, err := conn.Read(request)
	if err != nil {
		Log.Error(err)
		return
	}

	targetAddress, targetPort, err := ParseRequest(request[:n])
	if err != nil {
		Log.Error(err)
		return
	}

	method, err := Match(targetAddress)
	if err != nil {
		Log.Warn(targetAddress, " ", err)
	}

	switch method {
	case "REJECT":
		Log.Info("[REJECT] ", "Target: ", targetAddress, ":", targetPort)
		ruleForwardByReject(conn)
	case "PROXY":
		Log.Info("[PROXY] ", "Target: ", targetAddress, ":", targetPort)
		ruleForwardByProxy(conn, request, n, proxyAddr)
	case "DIRECT":
		Log.Info("[DIRECT] ", "Target: ", targetAddress, ":", targetPort)
		ruleForwardByDirect(conn, targetAddress, targetPort)
	default:
		Log.Error("Unknown method:", method, "Target: ", targetAddress, ":", targetPort)
	}
}

func ruleForwardByReject(conn net.Conn) {
	SendReply(conn, 0x02, net.IPv4(127, 0, 0, 1), 0)
}

func ruleForwardByProxy(conn net.Conn, request []byte, n int, proxyAddr string) {
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
		Log.Error("(FROM Proxy Server) Failed to connect to target server")
		return
	}

	// FORWARD DATA
	go io.Copy(ProxyConn, conn)
	io.Copy(conn, ProxyConn)
}

func ruleForwardByDirect(conn net.Conn, targetAddress string, targetPort int) {
	// 建立到目标服务器的连接
	targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetAddress, targetPort))
	if err != nil {
		Log.Error(err)
		return
	}
	defer targetConn.Close()

	reply := []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01}
	port := targetConn.LocalAddr().(*net.TCPAddr).Port
	reply = append(reply, byte(port>>8), byte(port&0xff))
	_, err = conn.Write(reply)
	if err != nil {
		Log.Error(err)
		return
	}

	// 数据转发
	go io.Copy(targetConn, conn)
	io.Copy(conn, targetConn)
}
