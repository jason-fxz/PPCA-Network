package main

import (
	"io"
	"log"
	"net"
)

var ListenAddr = "127.0.0.1:8081"
var proxyAddr = "127.0.0.1:1080"

func main() {
    // 1. 监听端口
    listener, err := net.Listen("tcp", ListenAddr)
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Println(err)
            continue
        }

        // 处理每个连接
        go handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
    defer conn.Close()

    if !negotiate(conn) {
        log.Println("Failed to negotiate with client")
        return
    }
    
    // 建立到代理服务器的连接
    ProxyConn, err := net.Dial("tcp", proxyAddr)
    if err != nil {
        log.Println(err)
        return
    }
    log.Println("Connected to Proxy Server:", proxyAddr)
    if !trynegotiate(ProxyConn) {
        log.Println("Failed to negotiate with Proxy Server")
        return
    }
    defer ProxyConn.Close()
    log.Println("Negotiated with Proxy Server SUCCESS")

    // FORWARD REQUEST
    request := make([]byte, 256)
    n, err := conn.Read(request)
    if err != nil {
        log.Println(err)
        return 
    }
    log.Println("Received Request:", request[:n])
    _, err = ProxyConn.Write(request[:n])
    if err != nil {
        log.Println(err)
        return
    }

    
    // FORWARD REPLY
    reply := make([]byte, 256)
    n, err = ProxyConn.Read(reply)
    if err != nil {
        log.Println(err)
        return
    }
    log.Println("(FROM Proxy Server) Received Reply:", reply[:n])
    conn.Write(reply[:n])
    if reply[1] != 0x00 {
        log.Println("(FROM Proxy Server) Failed to connect to target server")
        return
    }

    // FORWARD DATA
    go io.Copy(ProxyConn, conn)
    io.Copy(conn, ProxyConn)
}

func trynegotiate(conn net.Conn) bool {
    buf := []byte{0x05, 0x01, 0x00}
    _, err := conn.Write(buf)
    if err != nil {
        log.Println(err)
        return false
    }
    _, err = conn.Read(buf)
    if err != nil {
        log.Println(err)
        return false
    }
    if buf[1] != 0x00 {
        log.Println("Failed to use NO AUTHENTICATION REQUIRED")
        return false
    }
    return true
}

func negotiate(conn net.Conn) bool {
    // 实现版本协商和认证方式选择的逻辑
    // 读取客户端发送的协商请求
    // log.Println("============= BEGIN Negotiation =============")

    buf := make([]byte, 256)
    n, err := conn.Read(buf)
    if err != nil {
        log.Println(err)
        return false
    }

    // log.Println("Received:", buf[:n])

    // var version = buf[0]
    // var nMethods = buf[1]

    // 解析协商请求
    methods := buf[2 : n]
    var selectedMethod byte

    /*
        o  X'00' NO AUTHENTICATION REQUIRED
        o  X'01' GSSAPI
        o  X'02' USERNAME/PASSWORD
        o  X'03' to X'7F' IANA ASSIGNED
        o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
        o  X'FF' NO ACCEPTABLE METHODS
    */

    // log.Println("Version:", version)
    // log.Println("Number of Methods:", nMethods)
    // log.Println("Methods:", methods)


    // 遍历支持的认证方式，选择合适的方式
    for _, method := range methods {
        if method == 0x00 {
            selectedMethod = method
            break
        }
    }

    // log.Println("Selected Method:", selectedMethod)
    // defer log.Println("============== END Negotiation ==============")

    // 发送协商响应
    response := []byte{0x05, selectedMethod}
    _, err = conn.Write(response)
    if err != nil {
        log.Println(err)
        return false
    }

    return true
}
