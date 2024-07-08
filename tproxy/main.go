package main

import (
	"io"
	"log"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

func getOriginalDst(clientConn *net.TCPConn) ([]byte, error) {
	clientConnFile, err := clientConn.File()
	if err != nil {
		return []byte{}, err
	}
	defer clientConnFile.Close()

	fd := int(clientConnFile.Fd())
	var addr unix.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(addr))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(unix.SOL_IP), uintptr(unix.SO_ORIGINAL_DST), uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return []byte{}, errno
	}
	return []byte{addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3], 0, byte(addr.Port >> 8)}, nil
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	dest, err := getOriginalDst(conn.(*net.TCPConn))
	if err != nil {
		log.Printf("Failed to get original destination: %v", err)
		return
	}
	new_conn, err := net.Dial("tcp", "localhost:1080")
	if err != nil {
		return
	}
	defer new_conn.Close()
	buffer := make([]byte, 1024)
	new_conn.Write([]byte{0x05, 0x01, 0x00})
	_, err = new_conn.Read(buffer)
	if err != nil {
		return
	}
	if buffer[0] != 0x05 {
		panic("Unsupported SOCKS version")
	}
	if buffer[1] != 0x00 {
		panic("Unsupported authentication method")
	}
	response := []byte{0x05, 0x01, 0x00, 0x01, dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]}
	new_conn.Write(response)
	_, err = new_conn.Read(buffer)
	if err != nil {
		return
	}
	if buffer[1] != 0x00 {
		return
	}
	go io.Copy(new_conn, conn)
	io.Copy(conn, new_conn)
}

func main() {
	// 创建TCP套接字
	listener, err := net.Listen("tcp", "localhost:12345") // 使用0让系统自动选择端口
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("Failed to accept: %v", err)
		}
		go handleConnection(conn)
	}
}
