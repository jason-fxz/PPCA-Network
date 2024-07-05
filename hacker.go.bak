// Description:
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
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
        return header, fmt.Errorf("Invalid HTTP Request")
    }

    // check GET / HTTP/1.1
    if !strings.HasSuffix(lines[0], "HTTP/1.1") {
        return header, fmt.Errorf("Invalid HTTP Request (Note that we only support HTTP/1.1) %s", lines[0])
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
        go handleConnection(conn)
    }
}


func generateSignedCert(host string, caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey) error {
    // 为目标主机生成私钥
    privKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return err
    }

    // 创建证书模板
    certTemplate := x509.Certificate{
        SerialNumber: big.NewInt(1), // 在实际应用中，这应该是唯一的
        Subject: pkix.Name{
            Organization: []string{"Example Corp"},
        },
        NotBefore:             time.Now(),
        NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1年有效期
        KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
    }

    // 为证书模板添加主机名
    certTemplate.DNSNames = append(certTemplate.DNSNames, host)

    // 使用根证书私钥签发新证书
    certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, caCert, &privKey.PublicKey, caPrivateKey)
    if err != nil {
        return err
    }

    // 将私钥和证书序列化为 PEM 格式
    certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
    privKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

    // 保存或使用 certPEM 和 privKeyPEM
    // 例如，写入文件
    err = os.WriteFile("certs/" + host+"_cert.pem", certPEM, 0644)
    if err != nil {
        return err
    }
    err = os.WriteFile("certs/" + host +"_key.pem", privKeyPEM, 0644)
    if err != nil {
        return err
    }

    return nil
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
	
    targetAddress, targetPort, err := parseRequest(request[:n])
    if err != nil {
        Log.Error(err)
        return 
    }
    
    
    // Make a fake reply
    reply := []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00}
    conn.Write(reply)
    

    


    // Read the HTTP / TLS request
    bufn, buf, err := readtoBuffer(conn)
    if err != nil {
        Log.Error(err)
    }

    host := ""
    isTLS := false
    header, err := getHTTPHeader(buf)
    if err == nil {
        host = (*header)["Host"]
        Log.Info("Get Host FROM HTTP/1.1 Header: ", host)
    } else {
        sni, err := extractSNI(buf[:bufn])
        if err == nil {
            Log.Info("Get Host FROM TLS SNI: ", sni)
            host = sni
            isTLS = true
        } else {
            Log.Error("UnKnown Host from HTTP/1.1 Header and TLS SNI")
            return
        }
    }

    method, err := Match(host)
    if err != nil {
        Log.Warn(targetAddress, " ", err)
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
        forwardByDirectBufTLS(conn, targetAddress, targetPort, buf, bufn, isTLS)
    default:
        Log.Error("Unknown method:", method, "Target: ", targetAddress, ":", targetPort)
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



func forwardByDirectBufTLS(conn net.Conn, targetAddress string, targetPort int, buf []byte, bufn int, isTLS bool) {
    // 建立到目标服务器的连接
    if isTLS {
        targetConn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", targetAddress, targetPort), &tls.Config{
            InsecureSkipVerify: true,
        })
        if err != nil {
            Log.Error(err)
            return
        }
        defer targetConn.Close()
    
        // generateSignedCert()
        
        // 处理 conn 的 TLS 握手
        
        conn = tls.Server(conn, &tls.Config{
            
        })





    }


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


func readtoBuffer(conn net.Conn) (int, []byte, error) {
	var Buf bytes.Buffer
	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				return 0, nil, err
			}
			break
		}
		_, err = Buf.Write(buffer[:n])
		if err != nil {
			return 0, nil, err
		}
		if n < len(buffer) {
			break
		}
	}
	return Buf.Len(), Buf.Bytes(), nil
}

func writeFile(filename string, v ...interface{}) error {
    file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return err
    }
    defer file.Close()
    _, err = fmt.Fprintln(file, v...)
    return err
}


var addrToFunc = make(map[string]func(*http.Request, *http.Response) error)

func initModifyRules() {
    addrToFunc["poj.org:80"] = func(request *http.Request, response *http.Response) error {
        Log.Debug("Modifying response from poj.org:80")
        // Read the response body
        body, err := io.ReadAll(response.Body)
        if err != nil {
            return err
        }
        // Replace the desired string
        if request.URL.Path == "/" {
            body = bytes.Replace(body, []byte("Welcome To PKU JudgeOnline"), []byte("Welcome to ACM Class OnlineJudge"), -1)
            body = bytes.Replace(body, []byte("blue"), []byte("red"), -1)
            body = bytes.Replace(body, []byte("images/logo0.gif"), []byte("https://www.sjtu.edu.cn/resource/assets/img/LogoWhite.png"), -1)
            body = bytes.Replace(body, []byte("images/logo1.jpg"), []byte("https://www.sjtu.edu.cn/resource/upload/201811/20181114_061432_161.png"), -1)
        }
        if request.URL.Path == "/poj.css" {
            body = bytes.Replace(body, []byte("#6589d1"), []byte("#cf3c68"), -1)
            body = bytes.Replace(body, []byte("#6589D1"), []byte("#cf3c68"), -1)
        }

        // Update the response body with the modified content
        response.Body = io.NopCloser(bytes.NewReader(body))

        return nil
    }
}
// HTTP 捕获
func forwardData(cli net.Conn, srv net.Conn, addr string, port int) {
    if port != 443 {
        for true {
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