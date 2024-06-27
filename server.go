package main

import (
	"fmt"
	"io"
	"log"
	"net"
)

func main() {
    // 1. 监听端口
    listener, err := net.Listen("tcp", "127.0.0.1:1080")
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


    request := make([]byte, 256)
    n, err := conn.Read(request)
    if err != nil {
        log.Println(err)
        return 
    }

    log.Println("Received Request:", request[:n])
    
    // 解析请求的目标地址和端口
    targetAddress, targetPort, err := parseRequest(request[:n])
    if err != nil {
        log.Println(err)
        return 
    }

    // 建立到目标服务器的连接
    targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetAddress, targetPort))
    if err != nil {
        log.Println(err)
        return 
    }
    defer targetConn.Close()

    log.Println("Connected to Target Server:", targetAddress, targetPort)

    /*
        The SOCKS request information is sent by the client as soon as it has
        established a connection to the SOCKS server, and completed the
        authentication negotiations.  The server evaluates the request, and
        returns a reply formed as follows:

            +----+-----+-------+------+----------+----------+
            |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  | X'00' |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+

        Where:

            o  VER    protocol version: X'05'
            o  REP    Reply field:
                o  X'00' succeeded
                o  X'01' general SOCKS server failure
                o  X'02' connection not allowed by ruleset
                o  X'03' Network unreachable
                o  X'04' Host unreachable
                o  X'05' Connection refused
                o  X'06' TTL expired
                o  X'07' Command not supported
                o  X'08' Address type not supported
                o  X'09' to X'FF' unassigned
            o  RSV    RESERVED
            o  ATYP   address type of following address
                o  IP V4 address: X'01'
                o  DOMAINNAME: X'03'
                o  IP V6 address: X'04'
            o  BND.ADDR       server bound address
            o  BND.PORT       server bound port in network octet order

        Fields marked RESERVED (RSV) must be set to X'00'.

        If the chosen method includes encapsulation for purposes of
        authentication, integrity and/or confidentiality, the replies are
        encapsulated in the method-dependent encapsulation.
    */

    reply := []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01}
    port := targetConn.LocalAddr().(*net.TCPAddr).Port
    reply = append(reply, byte(port>>8), byte(port&0xff))
    _, err = conn.Write(reply)

    // 数据转发
    // biforwardData(conn, targetConn)
    go io.Copy(targetConn, conn)
    io.Copy(conn, targetConn)
}

func negotiate(conn net.Conn) bool {
    // 实现版本协商和认证方式选择的逻辑
    // 读取客户端发送的协商请求
    log.Println("============= BEGIN Negotiation =============")

    buf := make([]byte, 256)
    n, err := conn.Read(buf)
    if err != nil {
        log.Println(err)
        return false
    }

    log.Println("Received:", buf[:n])

    var version = buf[0]
    var nMethods = buf[1]

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

    log.Println("Version:", version)
    log.Println("Number of Methods:", nMethods)
    log.Println("Methods:", methods)


    // 遍历支持的认证方式，选择合适的方式
    for _, method := range methods {
        if method == 0x00 {
            selectedMethod = method
            break
        }
    }

    log.Println("Selected Method:", selectedMethod)
    defer log.Println("============== END Negotiation ==============")

    // 发送协商响应
    response := []byte{0x05, selectedMethod}
    _, err = conn.Write(response)
    if err != nil {
        log.Println(err)
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

func biforwardData(src, dst net.Conn) {
    buf := make([]byte, 4096)
    for {
        n, err := src.Read(buf)
        if err != nil {
            log.Println(err)
            return
        }

        _, err = dst.Write(buf[:n])
        if err != nil {
            log.Println(err)
            return
        }

        n, err = dst.Read(buf)
        if err != nil {
            log.Println(err)
            return
        }

        _, err = src.Write(buf[:n])
        if err != nil {
            log.Println(err)
            return
        }
        
    }
}