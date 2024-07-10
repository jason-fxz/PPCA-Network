// Description: A simple SOCKS5 proxy server that can capture HTTP/HTTPS requests and responses
package socks5

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

var rootCACert *x509.Certificate
var rootCAKey *rsa.PrivateKey

func Hacker(listenAddr string) {
	initModifyRules()
	var err error
	rootCACert, rootCAKey, err = LoadingCA("certs/mitmproxyCA.crt", "certs/mitmproxyCA.key")
	if err != nil {
		Log.Fatal(err)
	}
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
		go handleTLSConnection(conn)
	}
}

func LoadingCA(crt_path string, key_path string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// 读取跟证书
	rootCertPEM, err := os.ReadFile(crt_path)
	if err != nil {
		Log.Error(err)
		return nil, nil, err
	}
	rootKeyPEM, err := os.ReadFile(key_path)
	if err != nil {
		Log.Error(err)
		return nil, nil, err
	}
	// 解析根证书
	block, _ := pem.Decode(rootCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		Log.Error("failed to decode PEM block containing certificate")
		return nil, nil, errors.New("failed to decode PEM block containing certificate")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		Log.Error(err)
		return nil, nil, err
	}

	// 解析私钥
	block, _ = pem.Decode(rootKeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		Log.Error("failed to decode PEM block containing private key")
		return nil, nil, errors.New("failed to decode PEM block containing private key")
	}
	x509Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		Log.Error(err)
		return nil, nil, err
	}
	// 类型断言，确保x509Key是*rsa.PrivateKey类型
	rsaKey, ok := x509Key.(*rsa.PrivateKey)
	if !ok {
		Log.Error("x509Key is not of type *rsa.PrivateKey")
		return nil, nil, errors.New("x509Key is not of type *rsa.PrivateKey")
	}

	return x509Cert, rsaKey, nil
}

func generateFakeCert(host string, caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey) (*tls.Certificate, error) {
	// 为目标主机生成私钥
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	// 创建证书模板
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1), // 在实际应用中，这应该是唯一的
		Subject: pkix.Name{
			Organization: []string{"hacker"},
			CommonName:   host,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1年有效期
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	// 使用根证书私钥签发新证书
	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, caCert, &privKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}

	// 将私钥和证书序列化为 PEM 格式
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	privKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	// 保存或使用 certPEM 和 privKeyPEM
	// 例如，写入文件
	err = os.WriteFile("certs/"+host+"_cert.pem", certPEM, 0644)
	if err != nil {
		return nil, err
	}
	err = os.WriteFile("certs/"+host+"_key.pem", privKeyPEM, 0644)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, privKeyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func handleTLSConnection(conn net.Conn) {
	defer conn.Close()

	if !Negotiate(conn) {
		Log.Error("Failed to negotiate with client")
		return
	}

	// GET REQUEST
	_, targetAddress, targetPort, err := GetRequest(conn)
	if err != nil {
		Log.Error(err)
		return
	}

	// Make a fake reply
	SendReply(conn, 0, "127.0.0.1", 0)

	// Get host name from targetAddress
	host := targetAddress
	Log.Debug("Host:", host)

	if targetPort == 443 {
		cert, err := generateFakeCert(host, rootCACert, rootCAKey)
		if err != nil {
			Log.Error(err)
			return
		}
		tlsconn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{*cert},
		})

		targetConn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", targetAddress, targetPort), &tls.Config{
			// InsecureSkipVerify: true,
		})
		if err != nil {
			Log.Error(err)
			return
		}
		defer targetConn.Close()
		tlsconn.Handshake()

		// 数据转发
		forwardData(tlsconn, targetConn, targetAddress, targetPort)
	} else {
		targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetAddress, targetPort))
		if err != nil {
			Log.Error(err)
			return
		}
		defer targetConn.Close()
		forwardData(conn, targetConn, targetAddress, targetPort)
	}

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
	addrToFunc["example.com:443"] = func(request *http.Request, response *http.Response) error {
		Log.Debug("Modifying response from example.com:443")

		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		// Replace the desired string
		if request.URL.Path == "/" {
			body = bytes.Replace(body, []byte("Example"), []byte("Welcome to ACM Class OnlineJudge"), -1)
		}

		// Update the response body with the modified content
		response.Body = io.NopCloser(bytes.NewReader(body))

		return nil
	}
	addrToFunc["acm.sjtu.edu.cn:443"] = func(request *http.Request, response *http.Response) error {
		Log.Debug("Modifying response from acm.sjtu.edu.cn:443")
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		// Replace the desired string
		// if request.URL.Path == "/" {
		body = bytes.Replace(body, []byte("ACM"), []byte("JHON"), -1)
		// }

		// Update the response body with the modified content
		response.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	addrToFunc["www.baidu.com:443"] = func(request *http.Request, response *http.Response) error {
		Log.Debug("Modifying response from baidu.com:443")
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		body = bytes.Replace(body, []byte("百度"), []byte("谷歌"), -1)

		body = bytes.Replace(body, []byte("特朗普"), []byte("轴承原"), -1)

		body = bytes.Replace(body, []byte("Trump"), []byte("Luowen"), -1)

		// Update the response body with the modified content
		response.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

}
