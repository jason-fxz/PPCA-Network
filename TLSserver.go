package main

import (
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Hello, TLS!"))
}

func main() {
    http.HandleFunc("/", handler)

    // 配置TLS证书和私钥的路径
    keyPath := "certs/mitmproxyCA.key"
    certPath := "certs/mitmproxyCA.crt"

    // 启动HTTPS服务器
    log.Println("Starting TLS server on :443")
    err := http.ListenAndServeTLS(":443", certPath, keyPath, nil)
    if err != nil {
        log.Fatalf("ListenAndServeTLS error: %v", err)
    }
}