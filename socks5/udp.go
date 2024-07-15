package socks5

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type UDPMap struct {
	sync.Map // addr(to Client) <-> *Socks5UDPConn (to Target)
}

type Socks5UDPConn struct {
	sender  *net.UDPConn
	timeout time.Duration
	last    time.Time
	coTCP   *net.TCPConn
}

func (p *Socks5UDPConn) Close() {
	if p.sender != nil {
		p.sender.Close()
	}
	if p.coTCP != nil {
		p.coTCP.Close()
	}
}

func NewSocks5UDPConn(timeout time.Duration, coTCP *net.TCPConn) (*Socks5UDPConn, error) {
	return &Socks5UDPConn{
		sender:  nil,
		timeout: timeout,
		last:    time.Now(),
		coTCP:   coTCP,
	}, nil
}

func (p *UDPMap) Get(addr string) *Socks5UDPConn {
	conn, ok := p.Load(addr)
	if !ok {
		return nil
	}
	return conn.(*Socks5UDPConn)
}

func (p *UDPMap) Set(addr string, conn *Socks5UDPConn) {
	p.Store(addr, conn)
}

func (p *UDPMap) Del(addr string) *Socks5UDPConn {
	value, loaded := p.LoadAndDelete(addr)
	if !loaded {
		return nil
	}
	return value.(*Socks5UDPConn)
}

//          | UDP Relay Server |
// client -> relayer ==> senders -> server
// client <- relayer <== senders <- server

func runUDPRelayServer(listenAddr *net.UDPAddr, timeout time.Duration, udpmap *UDPMap) {
	relayer, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		Log.Fatal(err)
		return
	}
	defer relayer.Close()
	Log.Info("Start UDP relay server on ", relayer.LocalAddr())
	CheckUDPTimeout(udpmap, timeout*2)
	// var udpmap UDPMap
	buffer := make([]byte, 65536)
	for {
		n, cliAddr, err := relayer.ReadFrom(buffer)
		if err != nil {
			Log.Debug("Error reading from UDP: ", err)
			continue
		}
		udpConn := udpmap.Get(cliAddr.String())
		if udpConn.sender == nil {
			udpConn.sender, err = net.ListenUDP("udp", nil)
			if err != nil {
				continue
			}
			go func() {
				err := dataBackword(udpConn, relayer, cliAddr, timeout)
				if err != nil {
					Log.Debug("Error dataBackword: ", err)
				}
				udpConn := udpmap.Del(cliAddr.String())
				if udpConn != nil {
					udpConn.Close()
				}
			}()
		}
		err = dataForward(cliAddr, udpConn, buffer[:n])
		if err != nil {
			Log.Debug("Error dataForward: ", err)
			continue
		}
	}
}

func CheckUDPTimeout(udpmap *UDPMap, looptime time.Duration) {
	for {
		udpmap.Range(func(key, value interface{}) bool {
			conn := value.(*Socks5UDPConn)
			if time.Since(conn.last) > conn.timeout {
				Log.Info("UDP connection timeout: ", key.(string))
				udpmap.Del(key.(string))
				conn.Close()
			}
			return true
		})
		time.Sleep(looptime)
	}
}

func dataBackword(udpConn *Socks5UDPConn, relayer *net.UDPConn, cliAddr net.Addr, timeout time.Duration) error {
	buffer := make([]byte, 65536)
	for {
		udpConn.sender.SetReadDeadline(time.Now().Add(timeout))
		n, srvAddr, err := udpConn.sender.ReadFrom(buffer)
		if err != nil {
			// timeout or something
			continue
		}

		/*
			Each UDP datagram carries a UDP request header with it:
			+----+------+------+----------+----------+----------+
			|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
			+----+------+------+----------+----------+----------+
			| 2  |  1   |  1   | Variable |    2     | Variable |
			+----+------+------+----------+----------+----------+

			The fields in the UDP request header are:

			o  RSV  Reserved X'0000'
			o  FRAG    Current fragment number
			o  ATYP    address type of following addresses:
				o  IP V4 address: X'01'
				o  DOMAINNAME: X'03'
				o  IP V6 address: X'04'
			o  DST.ADDR       desired destination address
			o  DST.PORT       desired destination port
			o  DATA     user data
		*/

		udpAddr, ok := srvAddr.(*net.UDPAddr)
		if !ok {
			return fmt.Errorf("Error converting to UDPAddr")
		}
		addr := udpAddr.IP.String()
		port := udpAddr.Port
		buf := []byte{0x00, 0x00, 0x00, 0x00}
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
			buf = append(buf, net.ParseIP(addr).To4()...)
		case 0x03:
			buf = append(buf, byte(len(addr)))
			buf = append(buf, []byte(addr)...)
		case 0x04:
			buf = append(buf, net.ParseIP(addr).To16()...)
		}
		buf = append(buf, byte(port>>8), byte(port&0xff))
		buf = append(buf, buffer[:n]...)
		_, err = relayer.WriteTo(buf, cliAddr)
		if err != nil {
			continue
		}
		udpConn.last = time.Now()
		Log.Debug("[UDP] (Backword) ", srvAddr.String(), " -> ", cliAddr.String(), " ", len(buffer[:n]), " bytes")
		// Log.Debug("[BUF]", buffer[:n])
	}
}

func dataForward(cliAddr net.Addr, udpConn *Socks5UDPConn, buf []byte) error {
	frag := buf[2]
	if frag != 0x00 {
		return fmt.Errorf("unsupported FRAG: %d", frag)
	}
	atyp := buf[3]
	var addr string
	var n int
	switch atyp {
	case 0x01:
		addr = net.IP(buf[4:8]).String()
		n = 8
	case 0x03:
		addr = string(buf[5 : 5+int(buf[4])])
		n = 5 + int(buf[4])
	case 0x04:
		addr = "[" + net.IP(buf[4:20]).String() + "]"
		n = 20
	default:
		return fmt.Errorf("unsupported ATYP: %d", atyp)
	}
	srvAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", addr, int(buf[n])<<8|int(buf[n+1])))
	buf = buf[n+2:]
	if err != nil {
		return err
	}
	udpConn.last = time.Now()
	_, err = udpConn.sender.WriteTo(buf, srvAddr)
	if err != nil {
		return err
	}
	Log.Debug("[UDP] (Forword) ", cliAddr.String(), " -> ", srvAddr.String(), " ", len(buf), " bytes")
	// Log.Debug("[BUF]", buf)
	return nil
}
