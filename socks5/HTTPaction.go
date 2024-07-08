// Description: 代理客户端 - 规则匹配 by target address
package socks5

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func HTTPAction(listenAddr string, proxyAddr string, rulefile string) {
	InitHostRules(rulefile)
	initModifyRules()
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		Log.Fatal(err)
	}
	defer listener.Close()

	Log.Info("Listening on ", listenAddr)

	err = os.RemoveAll("./HTTPLog")
	if err != nil {
		Log.Error(err)
	}
	err = os.MkdirAll("./HTTPLog", os.ModePerm)
	if err != nil {
		Log.Error(err)
		return
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			Log.Warn(err)
			continue
		}
		// 处理每个连接
		go handleHTTPacitonConnection(conn, proxyAddr)
	}
}

func handleHTTPacitonConnection(conn net.Conn, proxyAddr string) {
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
		ruleHTTPforwardByProxy(conn, targetAddress, targetPort, proxyAddr)
	case "DIRECT":
		Log.Info("[DIRECT] ", "Target: ", targetAddress, ":", targetPort)
		forwardByDirect(conn, targetAddress, targetPort)
	default:
		Log.Error("Unknown method:", method, "Target: ", targetAddress, ":", targetPort)
	}
}

func ruleHTTPforwardByProxy(conn net.Conn, addr string, port int, proxyAddr string) {
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
	err = SendRequest(ProxyConn, 0x01, addr, port)
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
	err = SendReply(conn, rep, bindaddr, bindport)
	if err != nil {
		Log.Error(err)
		return
	}
	if rep != 0 {
		Log.Error("(FROM PROXY) Failed to connect to ", addr, ":", port, " (", rep, ")")
		return
	}

	// FORWARD DATA
	forwardData(conn, ProxyConn, addr, port)
}

func forwardByDirect(conn net.Conn, addr string, port int) {
	// 建立到目标服务器的连接
	targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		Log.Error(err)
		return
	}
	defer targetConn.Close()

	SendReply(conn, 0x00, targetConn.LocalAddr().String(), targetConn.LocalAddr().(*net.TCPAddr).Port)

	// 数据转发
	forwardData(conn, targetConn, addr, port)
}

// HTTP 捕获
func forwardData(cli net.Conn, srv net.Conn, addr string, port int) {
	if true {
		for {
			err := captureHTTP(cli, srv, addrToFunc[fmt.Sprintf("%s:%d", addr, port)])
			if err != nil {
				Log.Error(err)
				return
			}
		}
		// Log.Debug("HTTP Capture Done")
	} else {
		go io.Copy(srv, cli)
		io.Copy(cli, srv)
	}
}

func captureHTTP(cli net.Conn, srv net.Conn, handleResponse func(*http.Request, *http.Response) error) error {
	// defer cli.Close()

	// Get request from cli
	request, err := http.ReadRequest(bufio.NewReader(cli))
	if err != nil {
		Log.Error(err)
		Log.Debug(cli.RemoteAddr())
		return err
	}

	request.Header.Set("Accept-Encoding", "gzip")

	// 序列化 HTTP 请求到缓冲区
	var serializedRequest bytes.Buffer
	err = request.Write(&serializedRequest)
	if err != nil {
		Log.Error(err)
		return err
	}

	// 转发请求到 srv
	_, err = srv.Write(serializedRequest.Bytes())
	if err != nil {
		Log.Error(err)
		return err
	}

	// Get response from srv
	response, err := http.ReadResponse(bufio.NewReader(srv), request)
	if err != nil {
		Log.Error(err)
		return err
	}

	// 检查响应是否使用了 gzip 压缩
	if response.Header.Get("Content-Encoding") == "gzip" {
		// 创建 gzip 解压缩读取器
		gzipReader, err := gzip.NewReader(response.Body)
		if err != nil {
			Log.Error(err)
			return err
		}

		// 使用 bytes.Buffer 读取解压后的数据
		var decompressedBody bytes.Buffer
		_, err = io.Copy(&decompressedBody, gzipReader)
		if err != nil {
			Log.Error(err)
			return err
		}

		// 替换响应体为解压后的数据
		response.Body = io.NopCloser(&decompressedBody)
		response.Header.Del("Content-Encoding")
		gzipReader.Close()
	}

	// Call handleResponse function
	if handleResponse != nil {
		err = handleResponse(request, response)
		if err != nil {
			Log.Error(err)
			return err
		}
	}

	// 读取 response.Body 的全部内容
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		Log.Error(err)
		return err
	}
	// 确保后续操作可以重新读取 response.Body
	response.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// 获取 body 的长度
	bodyLength := len(bodyBytes)
	Log.Debug("Body length:", bodyLength)

	// 重新设置 Content-Length
	response.ContentLength = int64(bodyLength)
	response.Header.Set("Content-Length", fmt.Sprintf("%d", bodyLength))

	// 序列化 HTTP 响应到缓冲区
	var serializedResponse bytes.Buffer
	err = response.Write(&serializedResponse)
	if err != nil {
		Log.Error(err)
		return err
	}
	// Log
	err = writeFile(fmt.Sprintf("./HTTPLog/%s.log", time.Now().Format("2006-01-02_15.04.05")),
		"[Request]\r\n", serializedRequest.String(),
		"[Response]\r\n", serializedResponse.String(), "\r\n\r\n")
	if err != nil {
		Log.Error(err)
		return err
	}

	// 转发回复到 cli
	_, err = cli.Write(serializedResponse.Bytes())
	if err != nil {
		Log.Error(err)
		return err
	}
	return nil
}
