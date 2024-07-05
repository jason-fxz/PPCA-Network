// Description: 代理客户端 - 规则匹配 by HTTP / TLS
package socks5

import (
	"fmt"
	"io"
	"log"
	"net"
)

func ClientWithHTTPRule(listenAddr string, proxyAddr string, rulefile string) {
	InitHostRules(rulefile)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	Log.Info("Listening on ", listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			Log.Error(err)
			continue
		}
		// 处理每个连接
		go handleRuleHTTPConnection(conn, proxyAddr)
	}
}

func handleRuleHTTPConnection(conn net.Conn, proxyAddr string) {
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
	// log.Println("Received Request:", request[:n])

	targetAddress, targetPort, err := ParseRequest(request[:n])
	if err != nil {
		Log.Error(err)
		return
	}
	// log.Print("Target: ", targetAddress, ":", targetPort)

	// Make a fake reply
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00}
	conn.Write(reply)

	// Read the HTTP / TLS request
	bufn, buf, err := readtoBuffer(conn)
	if err != nil {
		Log.Error(err)
	}

	header, err := getHTTPHeader(buf)

	host := ""
	if err != nil {
		sni, err := extractSNI(buf[:bufn])
		if err == nil {
			Log.Info("Get Host FROM TLS SNI: ", sni)
			host = sni
		}
		// Log.Error(err)
	} else {
		host = (*header)["Host"]
		Log.Info("Get Host FROM HTTP/1.1 Header: ", host)
	}

	method, err := Match(host)
	if err != nil {
		Log.Warn(targetAddress, " ", err)
	}

	switch method {
	case "REJECT":
		Log.Info("[REJECT] ", "Target: ", targetAddress, ":", targetPort)
		ruleForwardByReject(conn)
	case "PROXY":
		Log.Info("[PROXY] ", "Target: ", targetAddress, ":", targetPort)
		ruleForwardByProxyBuf(conn, request, n, proxyAddr, buf, bufn)
	case "DIRECT":
		Log.Info("[DIRECT] ", "Target: ", targetAddress, ":", targetPort)
		ruleForwardByDirectBuf(conn, targetAddress, targetPort, buf, bufn)
	default:
		Log.Error("Unknown method: ", method, "Target: ", targetAddress, ":", targetPort)
	}
}

func ruleForwardByProxyBuf(conn net.Conn, request []byte, n int, proxyAddr string, buf []byte, bufn int) {
	// 建立到代理服务器的连接
	proxyConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		Log.Error(err)
		return
	}
	// log.Println("Connected to Proxy Server:", ProxyAddr)
	if !TryNegotiate(proxyConn) {
		Log.Error("Failed to negotiate with Proxy Server")
		return
	}
	defer proxyConn.Close()
	// log.Println("Negotiated with Proxy Server SUCCESS")

	// FORWARD REQUEST
	_, err = proxyConn.Write(request[:n])
	if err != nil {
		Log.Error(err)
		return
	}

	// FORWARD REPLY
	reply := make([]byte, 256)
	_, err = proxyConn.Read(reply)
	if err != nil {
		Log.Error(err)
		return
	}
	// We should not send the reply to the client, Since we have made a fake reply
	// conn.Write(reply[:n])
	if reply[1] != 0x00 {
		Log.Error("(FROM Proxy Server) Failed to connect to target server")
		return
	}

	// FORWARD DATA
	proxyConn.Write(buf[:bufn])
	go io.Copy(proxyConn, conn)
	io.Copy(conn, proxyConn)
}

func ruleForwardByDirectBuf(conn net.Conn, targetAddress string, targetPort int, buf []byte, bufn int) {
	// 建立到目标服务器的连接
	targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetAddress, targetPort))
	if err != nil {
		Log.Error(err)
		return
	}
	defer targetConn.Close()

	// 数据转发
	targetConn.Write(buf[:bufn])
	go io.Copy(targetConn, conn)
	io.Copy(conn, targetConn)
}
