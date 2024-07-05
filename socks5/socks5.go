// utils for socks5 protocol
package socks5

import (
	"fmt"
	"net"
)

func Negotiate(conn net.Conn) bool {
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
	methods := buf[2:n]
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

func ParseRequest(request []byte) (address string, port int, err error) {
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
		return "", 0, fmt.Errorf("request is too short: %v", request)
	}

	// 解析目标地址
	var targetAddress string
	switch request[3] {
	case 0x01:
		// IPv4
		targetAddress = net.IP(request[4:8]).String()
	case 0x03:
		// 域名
		len := int(request[4])
		targetAddress = string(request[5 : 5+len])
	case 0x04:
		// IPv6
		targetAddress = net.IP(request[4:20]).String()
	default:
		return "", 0, fmt.Errorf("unsupported address type: %v", request[3])
	}

	// 解析目标端口
	targetPort := int(request[len(request)-2])<<8 | int(request[len(request)-1])

	return targetAddress, targetPort, nil
}

func SendReply(conn net.Conn, rep byte, ip net.IP, port int) error {
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
	// Convert IP address to 4 bytes
	ipBytes := ip.To4()
	if ipBytes == nil {
		return fmt.Errorf("invalid IP address: %s", ip.String())
	}

	reply := []byte{0x05, rep, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01}

	reply = append(reply, byte(port>>8), byte(port&0xff))
	_, err := conn.Write(reply)
	return err
}

func TryNegotiate(conn net.Conn) bool {
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
