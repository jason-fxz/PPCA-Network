// Description: 代理客户端 - 规则匹配 by target address
package main

import (
	"fmt"
	"io"
	"net"
	"strconv"
)

var listenAddr = "127.0.0.1:8081"
var proxyAddr = "127.0.0.1:7897"

func main() {
    InitProcessRules("processrules.txt")
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
        go handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
    defer conn.Close()

    if !negotiate(conn) {
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
	
    targetAddress, targetPort, err := parseRequest(request[:n])
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
        forwardByReject(conn)
    case "PROXY":
        Log.Info("[PROXY] ", "Process: ", name, " PID: ", pid)
        forwardByProxy(conn, request, n)
    case "DIRECT":
        Log.Info("[DIRECT] ", "Process: ", name, " PID: ", pid)
        forwardByDirect(conn, targetAddress, targetPort)
    default:
        Log.Error("Unknown method: ", method, " Target: ", targetAddress, ":", targetPort)
    }
}

func forwardByReject(conn net.Conn) {
    reply := []byte{0x05, 0x02, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00}
    conn.Write(reply)
}

func forwardByProxy(conn net.Conn, request []byte, n int) {
    // 建立到代理服务器的连接
    ProxyConn, err := net.Dial("tcp", proxyAddr)
    if err != nil {
        Log.Error(err)
        return
    }
    // log.Println("Connected to Proxy Server:", ProxyAddr)
    if !trynegotiate(ProxyConn) {
        Log.Error("Failed to negotiate with Proxy Server")
        return
    }
    defer ProxyConn.Close()
    // log.Println("Negotiated with Proxy Server SUCCESS")

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
    // log.Println("(FROM Proxy Server) Received Reply:", reply[:n])
    conn.Write(reply[:n])
    if reply[1] != 0x00 {
        Log.Error("(FROM Proxy Server) Failed to connect to target server")
        return
    }

    // FORWARD DATA
    go io.Copy(ProxyConn, conn)
    io.Copy(conn, ProxyConn)
}

func forwardByDirect(conn net.Conn, targetAddress string, targetPort int) {
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

    // 数据转发
    go io.Copy(targetConn, conn)
    io.Copy(conn, targetConn)
}

func trynegotiate(conn net.Conn) bool {
    buf := []byte{0x05, 0x01, 0x00}
    _, err := conn.Write(buf)
    if err != nil {
        Log.Error(err)
        return false
    }
    _, err = conn.Read(buf)
    if err != nil {
        Log.Error(err)
        return false
    }
    if buf[1] != 0x00 {
        Log.Error("Failed to use NO AUTHENTICATION REQUIRED")
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
        Log.Error(err)
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
        Log.Error(err)
        return false
    }

    return true
}

func parseRequest(request []byte) (address string, port int, err error) {
    /*
     The SOCKS request is formed as follows:

        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

     Where:

          o  VER    protocol version: X'05'
          o  CMD
             o  CONNECT X'01'
             o  BIND X'02'
             o  UDP ASSOCIATE X'03'
          o  RSV    RESERVED
          o  ATYP   address type of following address
             o  IP V4 address: X'01'  the address is a version-4 IP address, with a length of 4 octets
             o  DOMAINNAME: X'03'  the address field contains a fully-qualified domain name.  The first
                octet of the address field contains the number of octets of name that
                follow, there is no terminating NUL octet.
             o  IP V6 address: X'04' the address is a version-6 IP address, with a length of 16 octets.
          o  DST.ADDR       desired destination address
          o  DST.PORT desired destination port in network octet
             order
    */
    if len(request) < 6 {
        return "", 0, fmt.Errorf("Request is too short: %v", request)
    }

    // 解析目标地址
    var targetAddress string
    switch request[3] {
    case 0x01:
        // IPv4
        targetAddress = net.IP(request[4 : 8]).String()
    case 0x03:
        // 域名
        len := int(request[4])
        targetAddress = string(request[5 : 5 + len])
    case 0x04:
        // IPv6
        targetAddress = net.IP(request[4 : 20]).String()
    default:
        return "", 0, fmt.Errorf("Unsupported address type: %v", request[3])
    }

    // 解析目标端口
    targetPort := int(request[len(request)-2])<<8 | int(request[len(request)-1])

    return targetAddress, targetPort, nil
}
