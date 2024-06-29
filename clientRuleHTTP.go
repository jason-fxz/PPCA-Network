// Description: 代理客户端 - 规则匹配 by HTTP / TLS
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

var listenAddr = "127.0.0.1:8081"
var proxyAddr = "127.0.0.1:7897"

type HTTPHeader map[string]string   // HTTP 头部

// WTF!!
// 解析 TLS ClientHello 报文并提取 SNI 
func extractSNI(clientHello []byte) (string, error) {
	if len(clientHello) < 5 || clientHello[0] != 0x16 {
		return "", fmt.Errorf("not a valid TLS ClientHello message")
	}

	recordLength := int(binary.BigEndian.Uint16(clientHello[3:5]))
	if len(clientHello) < 5+recordLength {
		return "", fmt.Errorf("incomplete TLS record")
	}

	clientHello = clientHello[5 : 5+recordLength]
	if len(clientHello) < 38 {
		return "", fmt.Errorf("invalid ClientHello length")
	}

	sessionIDLength := int(clientHello[38])
	if len(clientHello) < 39+sessionIDLength {
		return "", fmt.Errorf("invalid session ID length")
	}

	clientHello = clientHello[39+sessionIDLength:]
	if len(clientHello) < 2 {
		return "", fmt.Errorf("invalid cipher suites length")
	}

	cipherSuitesLength := int(binary.BigEndian.Uint16(clientHello[:2]))
	if len(clientHello) < 2+cipherSuitesLength {
		return "", fmt.Errorf("invalid cipher suites length")
	}

	clientHello = clientHello[2+cipherSuitesLength:]
	if len(clientHello) < 1 {
		return "", fmt.Errorf("invalid compression methods length")
	}

	compressionMethodsLength := int(clientHello[0])
	if len(clientHello) < 1+compressionMethodsLength {
		return "", fmt.Errorf("invalid compression methods length")
	}

	clientHello = clientHello[1+compressionMethodsLength:]
	if len(clientHello) < 2 {
		return "", fmt.Errorf("invalid extensions length")
	}

	extensionsLength := int(binary.BigEndian.Uint16(clientHello[:2]))
	clientHello = clientHello[2:]
	if len(clientHello) < extensionsLength {
		return "", fmt.Errorf("invalid extensions length")
	}

	for len(clientHello) >= 4 {
		extensionType := binary.BigEndian.Uint16(clientHello[:2])
		extensionDataLength := int(binary.BigEndian.Uint16(clientHello[2:4]))

		if len(clientHello) < 4+extensionDataLength {
			return "", fmt.Errorf("invalid extension data length")
		}

		if extensionType == 0x0000 {
			serverNameList := clientHello[4:4+extensionDataLength]
			if len(serverNameList) < 2 {
				return "", fmt.Errorf("invalid server name list length")
			}

			serverNameLength := int(binary.BigEndian.Uint16(serverNameList[:2]))
			serverNameList = serverNameList[2:]
			if len(serverNameList) < serverNameLength {
				return "", fmt.Errorf("invalid server name length")
			}

			for len(serverNameList) >= 3 {
				nameType := serverNameList[0]
				nameLength := int(binary.BigEndian.Uint16(serverNameList[1:3]))

				if len(serverNameList) < 3+nameLength {
					return "", fmt.Errorf("invalid server name length")
				}

				if nameType == 0 {
					return string(serverNameList[3 : 3+nameLength]), nil
				}

				serverNameList = serverNameList[3+nameLength:]
			}
		}

		clientHello = clientHello[4+extensionDataLength:]
	}

	return "", fmt.Errorf("SNI not found")
}


func getHTTPHeader(data []byte) (*HTTPHeader, error) {
    header := &HTTPHeader{}
    // 将byte[]转换为字符串
    text := string(data)
    // 按行分割
    lines := strings.Split(text, "\r\n")
    if len(lines) < 2 {
        return nil, fmt.Errorf("Invalid HTTP Request")
    }

    // check GET / HTTP/1.1
    if !strings.HasSuffix(lines[0], "HTTP/1.1") {
        return nil, fmt.Errorf("Invalid HTTP Request (Note that we only support HTTP/1.1) %s", lines[0])
    }

    for _, line := range lines {
        // 按冒号分隔键和值
        parts := strings.SplitN(line, ":", 2)
        if len(parts) == 2 {
            key := strings.TrimSpace(parts[0])
            value := strings.TrimSpace(parts[1])
            // 添加到Headers中
            (*header)[key] = value
        }
    }
    return header, nil
}


func main() {
    InitHostRules("autoproxy.txt")
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

    // Make a fake reply
    reply := []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00}
    conn.Write(reply)

    // Read the HTTP / TLS request
    buf := make([]byte, 4096)
    bufn, err := conn.Read(buf)
    if err != nil {
        Log.Error(err)
    }

    
    header, err := getHTTPHeader(buf)

    host := ""
    if err != nil {
        sni, err := extractSNI(buf[:bufn])
        if err != nil {
            // log.Println("Extract SNI failed:", err)
        }
        Log.Info("Get Host FROM TLS SNI: ", sni)
        host = sni
        // Log.Error(err)
    } else {
        host = (*header)["Host"]
        Log.Info("Get Host FROM HTTP/1.1 Header: ", host)
    }
    
    method, err := Match(host)
    if err != nil {
        Log.Warn(targetAddress, " ",err)
    }

    switch method {
    case "REJECT":
        Log.Info("[REJECT] ", "Target: ", targetAddress, ":", targetPort)
        forwardByReject(conn)
    case "PROXY":
        Log.Info("[PROXY] ", "Target: ", targetAddress, ":", targetPort)
        forwardByProxyBuf(conn, request, n, buf, bufn)
    case "DIRECT":
        Log.Info("[DIRECT] ", "Target: ", targetAddress, ":", targetPort)
        forwardByDirectBuf(conn, targetAddress, targetPort, buf, bufn)
    default:
        Log.Error("Unknown method: ", method, "Target: ", targetAddress, ":", targetPort)
    }
}

func forwardByReject(conn net.Conn) {
    reply := []byte{0x05, 0x02, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00}
    conn.Write(reply)
}

func forwardByProxyBuf(conn net.Conn, request []byte, n int, buf []byte, bufn int) {
    // 建立到代理服务器的连接
    proxyConn, err := net.Dial("tcp", proxyAddr)
    if err != nil {
        Log.Error(err)
        return
    }
    // log.Println("Connected to Proxy Server:", ProxyAddr)
    if !trynegotiate(proxyConn) {
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
    n, err = proxyConn.Read(reply)
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

func forwardByDirectBuf(conn net.Conn, targetAddress string, targetPort int, buf []byte, bufn int) {
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
