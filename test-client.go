package main

import (
	"io/ioutil"
	"log"
	"net/http"

	"golang.org/x/net/proxy"
)

func main() {
    // 创建一个 SOCKS5 代理拨号器
    dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:8081", nil, proxy.Direct)
    if err != nil {
        log.Fatalf("Error creating SOCKS5 dialer: %v", err)
    }

    // 创建一个 HTTP 客户端，并使用 SOCKS5 代理拨号器
    transport := &http.Transport{Dial: dialer.Dial}
    client := &http.Client{Transport: transport}

    // 通过 SOCKS5 代理发送 HTTP 请求
    resp, err := client.Get("http://example.com/3")
    if err != nil {
        log.Fatalf("Error making HTTP request: %v", err)
    }
    defer resp.Body.Close()

    // 读取并打印响应内容
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Fatalf("Error reading response body: %v", err)
    }
    log.Printf("Response: %s", body)
}
