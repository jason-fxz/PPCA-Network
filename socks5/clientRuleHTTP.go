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
	targetAddress, targetPort, err := GetRequest(conn)
	if err != nil {
		Log.Error(err)
		return
	}
	// Make a fake reply
	SendReply(conn, 0, "127.0.0.1", 0)

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
		ruleForwardByProxyBuf(conn, targetAddress, targetPort, proxyAddr, buf, bufn)
	case "DIRECT":
		Log.Info("[DIRECT] ", "Target: ", targetAddress, ":", targetPort)
		ruleForwardByDirectBuf(conn, targetAddress, targetPort, buf, bufn)
	default:
		Log.Error("Unknown method: ", method, "Target: ", targetAddress, ":", targetPort)
	}
}

func ruleForwardByProxyBuf(conn net.Conn, addr string, port int, proxyAddr string, buf []byte, bufn int) {
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
	err = SendRequest(proxyConn, 0x01, addr, port)
	if err != nil {
		Log.Error(err)
		return
	}

	// FORWARD REPLY
	rep, _, _, err := GetReply(proxyConn)
	if err != nil {
		Log.Error(err)
		return
	}
	// We should not send the reply to the client, Since we have made a fake reply
	if rep != 0x00 {
		Log.Error("(FROM PROXY) Failed to connect to ", addr, ":", port, " (", rep, ")")
		return
	}

	// FORWARD DATA
	proxyConn.Write(buf[:bufn])
	go io.Copy(proxyConn, conn)
	io.Copy(conn, proxyConn)
}

func ruleForwardByDirectBuf(conn net.Conn, addr string, port int, buf []byte, bufn int) {
	// 建立到目标服务器的连接
	targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", addr, port))
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
