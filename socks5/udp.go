package socks5

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type UDPMap struct {
	sync.Map // addr(to Client) <-> UDPConn (to Target)
}

func (p *UDPMap) Get(addr string) *net.UDPConn {
	conn, ok := p.Load(addr)
	if !ok {
		return nil
	}
	return conn.(*net.UDPConn)
}

func (p *UDPMap) Set(addr string, conn *net.UDPConn) {
	p.Store(addr, conn)
}

func (p *UDPMap) Del(addr string) *net.UDPConn {
	value, loaded := p.LoadAndDelete(addr)
	if !loaded {
		return nil
	}
	return value.(*net.UDPConn)
}

//          | UDP Relay Server |
// client -> relayer ==> senders -> server
// client <- relayer <== senders <- server

func runUDPRelayServer(listenAddr *net.UDPAddr, timeout time.Duration) {
	relayer, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		Log.Fatal(err)
		return
	}
	defer relayer.Close()
	Log.Info("Start UDP relay server on ", relayer.LocalAddr())
	var udpmap UDPMap
	buffer := make([]byte, 65536)
	for {
		n, cliAddr, err := relayer.ReadFrom(buffer)
		Log.Debug("Get UDP ", cliAddr)
		if err != nil {
			// Log.Error("Error reading from UDP: ", err)
			continue
		}
		sender := udpmap.Get(cliAddr.String())
		if sender == nil {
			sender, err = net.ListenUDP("udp", nil)
			if err != nil {
				continue
			}
			udpmap.Set(cliAddr.String(), sender)

			go func() {
				err := dataBackword(sender, relayer, cliAddr, timeout)
				if err != nil {
					// Log.Error("Error dataBackword: ", err)
				}
				sender := udpmap.Del(cliAddr.String())
				if sender != nil {
					sender.Close()
				}
			}()
		}
		err = dataForward(cliAddr, sender, buffer[:n])
		if err != nil {
			// Log.Error("Error dataForward: ", err)
			continue
		}

	}
}

func dataBackword(sender *net.UDPConn, relayer *net.UDPConn, cliAddr net.Addr, timeout time.Duration) error {
	buffer := make([]byte, 65536)
	for {
		sender.SetReadDeadline(time.Now().Add(timeout))
		n, srvAddr, err := sender.ReadFrom(buffer)
		if err != nil {
			return err
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
		buf := []byte{0x00, 0x00, 0x00, 0x00}
		if net.ParseIP(srvAddr.String()) == nil {
			buf[3] = 0x03 // domain
		} else {
			if net.ParseIP(srvAddr.String()).To4() != nil {
				buf[3] = 0x01 // ipv4
			} else if net.ParseIP(srvAddr.String()).To16() != nil {
				buf[3] = 0x04 // ipv6
			}
		}
		switch buf[3] {
		case 0x01:
			buf = append(buf, net.ParseIP(srvAddr.String()).To4()...)
		case 0x03:
			buf = append(buf, byte(len(srvAddr.String())))
			buf = append(buf, []byte(srvAddr.String())...)
		case 0x04:
			buf = append(buf, net.ParseIP(srvAddr.String()).To16()...)
		}
		buf = append(buf, byte(srvAddr.(*net.UDPAddr).Port>>8), byte(srvAddr.(*net.UDPAddr).Port&0xff))
		buf = append(buf, buffer[:n]...)
		_, err = relayer.WriteTo(buf, cliAddr)
		if err != nil {
			return err
		}
		Log.Info("[UDP] (Backword) ", srvAddr.String(), " -> ", cliAddr.String(), " ", len(buf), " bytes")
	}
}

func dataForward(cliAddr net.Addr, sender *net.UDPConn, buf []byte) error {
	frag := buf[2]
	if frag != 0x00 {
		return fmt.Errorf("unsupported FRAG: %d", frag)
	}
	atyp := buf[3]
	var srvAddr string
	var n int
	switch atyp {
	case 0x01:
		srvAddr = net.IP(buf[4:8]).String()
		n = 8
	case 0x03:
		srvAddr = string(buf[5 : 5+int(buf[4])])
		n = 5 + int(buf[4])
	case 0x04:
		srvAddr = "[" + net.IP(buf[4:20]).String() + "]"
		n = 20
	default:
		return fmt.Errorf("unsupported ATYP: %d", atyp)
	}
	srvAddr = fmt.Sprintf("%s:%d", srvAddr, int(buf[n])<<8|int(buf[n+1]))
	buf = buf[n+2:]
	srvudpAddr, err := net.ResolveUDPAddr("udp", srvAddr)
	if err != nil {
		return err
	}
	_, err = sender.WriteTo(buf, srvudpAddr)
	if err != nil {
		return err;
	}
	Log.Info("[UDP] (Forword) ", cliAddr.String(), " -> ", srvudpAddr.String(), " ", len(buf), " bytes")
	return nil
}
