// utils for socks5 protocol
package socks5

import (
	"fmt"
	"io"
	"net"
)

func Negotiate(conn net.Conn) bool {
	/*
	   The client connects to the server, and sends a version
	   identifier/method selection message:

	                   +----+----------+----------+
	                   |VER | NMETHODS | METHODS  |
	                   +----+----------+----------+
	                   | 1  |    1     | 1 to 255 |
	                   +----+----------+----------+

	   The VER field is set to X'05' for this version of the protocol.  The
	   NMETHODS field contains the number of method identifier octets that
	   appear in the METHODS field.

	   The server selects from one of the methods given in METHODS, and
	   sends a METHOD selection message:

	                         +----+--------+
	                         |VER | METHOD |
	                         +----+--------+
	                         | 1  |   1    |
	                         +----+--------+

	   If the selected METHOD is X'FF', none of the methods listed by the
	   client are acceptable, and the client MUST close the connection.

	   The values currently defined for METHOD are:

	          o  X'00' NO AUTHENTICATION REQUIRED
	          o  X'01' GSSAPI
	          o  X'02' USERNAME/PASSWORD
	          o  X'03' to X'7F' IANA ASSIGNED
	          o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
	          o  X'FF' NO ACCEPTABLE METHODS

	   The client and server then enter a method-specific sub-negotiation.
	*/

	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		Log.Error(err)
		return false
	}
	var nMethods = buf[1]
	methods := make([]byte, nMethods)
	_, err = io.ReadFull(conn, methods)
	if err != nil {
		Log.Error(err)
		return false
	}

	// 解析协商请求
	var selectedMethod byte

	// 遍历支持的认证方式，选择合适的方式
	for _, method := range methods {
		if method == 0x00 {
			selectedMethod = method
			break
		}
	}

	// 发送协商响应
	response := []byte{0x05, selectedMethod}
	_, err = conn.Write(response)
	if err != nil {
		Log.Error(err)
		return false
	}

	return true
}

func GetRequest(conn net.Conn) (cmd byte, addr string, port int, err error) {
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
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return
	}
	cmd = byte(buf[1])

	switch buf[3] {
	case 0x01:
		// IPv4
		buf1 := make([]byte, 6)
		_, err = io.ReadFull(conn, buf1)
		if err != nil {
			return
		}
		addr = net.IP(buf1[0:4]).String()
		port = int(buf1[4])<<8 | int(buf1[5])
	case 0x03:
		// 域名
		buflen := make([]byte, 1)
		_, err = io.ReadFull(conn, buflen)
		if err != nil {
			return
		}
		len := int(buflen[0])
		buf3 := make([]byte, len+2)
		_, err = io.ReadFull(conn, buf3)
		if err != nil {
			return
		}
		addr = string(buf3[:len])
		port = int(buf3[len])<<8 | int(buf3[len+1])
	case 0x04:
		// IPv6
		buf4 := make([]byte, 18)
		_, err = io.ReadFull(conn, buf4)
		if err != nil {
			return
		}
		addr = "[" + net.IP(buf4[0:16]).String() + "]"
		port = int(buf4[16])<<8 | int(buf4[17])
	default:
		return cmd, "", 0, fmt.Errorf("unsupported address type: %v", buf[3])
	}
	return
}

func SendRequest(conn net.Conn, cmd byte, addr string, port int) error {
	buf := make([]byte, 4)
	buf[0] = 0x05 // Version
	buf[1] = cmd  // CMD
	buf[2] = 0x00 // RESERVED
	// Address type
	if net.ParseIP(addr) == nil {
		buf[3] = 0x03 // domain
	} else {
		if net.ParseIP(addr).To4() != nil {
			buf[3] = 0x01 // ipv4
		} else if net.ParseIP(addr).To16() != nil {
			buf[3] = 0x04 // ipv6
		}
	}
	switch buf[3] {
	case 0x01:
		// IPv4
		ip := net.ParseIP(addr).To4()
		buf = append(buf, ip...)
	case 0x03:
		// domain
		buf = append(buf, byte(len(addr)))
		buf = append(buf, []byte(addr)...)
	case 0x04:
		// IPv6
		ip := net.ParseIP(addr).To16()
		buf = append(buf, ip...)
	default:
		return fmt.Errorf("unsupported address type: %v", buf[3])
	}
	buf = append(buf, byte(port>>8), byte(port&0xff))
	_, err := conn.Write(buf)
	if err != nil {
		return err
	}
	return nil
}

func GetReply(conn net.Conn) (rep byte, addr string, port int, err error) {
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
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return
	}
	if buf[0] != 0x05 {
		err = fmt.Errorf("unsupported SOCKS version: %v", buf[0])
		return
	}
	rep = buf[1]
	atyp := buf[3]
	switch atyp {
	case 0x01:
		// IPv4
		buf1 := make([]byte, 6)
		_, err = io.ReadFull(conn, buf1)
		if err != nil {
			return
		}
		addr = net.IP(buf1[0:4]).String()
		port = int(buf1[4])<<8 | int(buf1[5])
	case 0x03:
		// domain
		buflen := make([]byte, 1)
		_, err = io.ReadFull(conn, buflen)
		if err != nil {
			return
		}
		len := int(buflen[0])
		buf3 := make([]byte, len+2)
		_, err = io.ReadFull(conn, buf3)
		if err != nil {
			return
		}
		addr = string(buf3[:len])
		port = int(buf3[len])<<8 | int(buf3[len+1])
	case 0x04:
		// IPv6
		buf4 := make([]byte, 18)
		_, err = io.ReadFull(conn, buf4)
		if err != nil {
			return
		}
		addr = "[" + net.IP(buf4[0:16]).String() + "]"
		port = int(buf4[16])<<8 | int(buf4[17])
	default:
		err = fmt.Errorf("unsupported address type: %v", atyp)
		return
	}
	return
}

func SendReply(conn net.Conn, rep byte, addr string, port int) error {
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
	var atyp byte = 0x00
	if net.ParseIP(addr) == nil {
		atyp = 0x03
	} else {
		if net.ParseIP(addr).To4() != nil {
			atyp = 0x01
		} else if net.ParseIP(addr).To16() != nil {
			atyp = 0x04
		}
	}
	buf := make([]byte, 4)
	buf[0] = 0x05 // Version
	buf[1] = rep  // Reply field
	buf[2] = 0x00 // RESERVED
	buf[3] = atyp // Address type
	switch atyp {
	case 0x01:
		// IPv4
		ip := net.ParseIP(addr).To4()
		buf = append(buf, ip...)
	case 0x03:
		// domain
		buf = append(buf, byte(len(addr)))
		buf = append(buf, []byte(addr)...)
	case 0x04:
		// IPv6
		ip := net.ParseIP(addr).To16()
		buf = append(buf, ip...)
	default:
		return fmt.Errorf("unsupported address type: %v", atyp)
	}
	buf = append(buf, byte(port>>8), byte(port&0xff))
	_, err := conn.Write(buf)
	if err != nil {
		return err
	}
	return nil
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
