package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

type HTTPHeader map[string]string // HTTP 头部

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
			serverNameList := clientHello[4 : 4+extensionDataLength]
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
		return header, fmt.Errorf("invalid HTTP Request")
	}

	// check GET / HTTP/1.1
	if !strings.HasSuffix(lines[0], "HTTP/1.1") {
		return header, fmt.Errorf("invalid HTTP Request (Note that we only support HTTP/1.1) %s", lines[0])
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
