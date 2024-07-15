package socks5

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

type Server struct {
	listenAddr    *net.TCPAddr
	udpListenAddr *net.UDPAddr
	timeout       time.Duration
	udpmap        *UDPMap
}

func NewServer(listenAddr string, udpListenAddr string, timeout time.Duration) (*Server, error) {
	tcp, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	udp := &net.UDPAddr{}
	if udpListenAddr != "" {
		udp, err = net.ResolveUDPAddr("udp", udpListenAddr)
		if err != nil {
			return nil, err
		}
	}

	return &Server{
		listenAddr:    tcp,
		udpListenAddr: udp,
		timeout:       timeout,
		udpmap:        &UDPMap{},
	}, nil
}

func (s *Server) Run() {
	listener, err := net.ListenTCP("tcp", s.listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	Log.Info("Start server on ", listener.Addr())
	defer listener.Close()
	if err != nil {
		log.Fatal(err)
	}

	go runUDPRelayServer(s.udpListenAddr, 30*time.Second, s.udpmap)

	for {
		conn, err := listener.Accept()
		if err != nil {
			Log.Error(err)
			continue
		}
		go s.handleServerConnection(conn, s.udpListenAddr)
	}
}

func RunServer(listenAddr string, udpListenAddr string) {
	server, err := NewServer(listenAddr, udpListenAddr, 30*time.Second)
	if err != nil {
		Log.Fatal(err)
	}
	server.Run()

}

func (s *Server) handleServerConnection(conn net.Conn, udpListenAddr *net.UDPAddr) {
	// Log.Debug("New connection from ", conn.RemoteAddr())

	if !Negotiate(conn) {
		Log.Error("Failed to negotiate with client")
		return
	}

	// 解析请求的目标地址和端口
	cmd, addr, port, err := GetRequest(conn)
	if err != nil {
		Log.Error(err)
		return
	}
	if cmd == 0x01 {
		// TCP
		targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", addr, port))
		if err != nil {
			Log.Error(err)
			return
		}
		defer targetConn.Close()

		Log.Info("[TCP] ", conn.RemoteAddr(), " -> ", addr, ":", port)

		SendReply(conn, 0, targetConn.RemoteAddr().(*net.TCPAddr).IP.String(), targetConn.RemoteAddr().(*net.TCPAddr).Port)

		// 数据转发
		go io.Copy(targetConn, conn)
		io.Copy(conn, targetConn)
		conn.Close()
	} else if cmd == 0x03 {
		// UDP
		Log.Info("[UDP ASSOCIATE] ", conn.RemoteAddr())
		udpconn, err := NewSocks5UDPConn(s.timeout, conn.(*net.TCPConn))
		if err != nil {
			conn.Close()
			Log.Error(err)
			return
		}
		// CASE1 : refer to RFC, use the addr/port client send to you
		// This will NOT work !! Since many socks5 client send you destination addr/port
		// s.udpmap.Set(fmt.Sprintf("%s:%d", addr, port), udpconn)

		// CASE2: we bind it to the first request in the same source ip
		s.udpmap.AddWhitelist(conn.RemoteAddr().(*net.TCPAddr).IP.String(), udpconn)

		err = SendReply(conn, 0, conn.LocalAddr().(*net.TCPAddr).IP.String(), udpListenAddr.Port)
		if err != nil {
			conn.Close()
			Log.Error(err)
			return
		}
	}
}
