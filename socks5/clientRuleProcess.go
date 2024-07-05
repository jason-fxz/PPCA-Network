// Description: 代理客户端 - 规则匹配 by target address
package socks5

import (
	"net"
	"strconv"
)

func ClientWithRuleProcess(listenAddr string, proxyAddr string, processRules string) {
	InitProcessRules(processRules)
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
		go handleRuleProcessConnection(conn, proxyAddr)
	}
}

func handleRuleProcessConnection(conn net.Conn, proxyAddr string) {
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

	// Get the Port
	port := conn.RemoteAddr().(*net.TCPAddr).Port
	// log.Println("port:", strconv.Itoa(port))
	name, pid, err := GetProcessByPort(strconv.Itoa(port))
	if err != nil {
		Log.Error(err)
		return
	}

	// log.Println("Process:", name, " PID:", pid)

	method, err := Match(name)
	if err != nil {
		Log.Warn(targetAddress, " ", err)
	}

	switch method {
	case "REJECT":
		Log.Info("[REJECT] ", "Process: ", name, " PID: ", pid)
		ruleForwardByReject(conn)
	case "PROXY":
		Log.Info("[PROXY] ", "Process: ", name, " PID: ", pid)
		ruleForwardByProxy(conn, request, n, proxyAddr)
	case "DIRECT":
		Log.Info("[DIRECT] ", "Process: ", name, " PID: ", pid)
		ruleForwardByDirect(conn, targetAddress, targetPort)
	default:
		Log.Error("Unknown method: ", method, " Target: ", targetAddress, ":", targetPort)
	}
}
