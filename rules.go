package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)



type hostrule struct {
	typ     byte   // 0x00 for regex | 0x01 for CIDR
	pattern string
	method  string // PROXY | DIRECT | REJECT
}



// isIPInCIDR 检查一个 IP 是否在指定的 CIDR 范围内
func isIPInCIDR(ipStr string, cidrStr string) (bool, error) {
    // 解析 IP 地址
    ip := net.ParseIP(ipStr)
    if ip == nil {
        return false, fmt.Errorf("invalid IP address: %s", ipStr)
    }

    // 解析 CIDR
    _, ipNet, err := net.ParseCIDR(cidrStr)
    if err != nil {
        return false, fmt.Errorf("invalid CIDR: %s", cidrStr)
    }

    // 检查 IP 是否在 CIDR 范围内
    return ipNet.Contains(ip), nil
}

// 用于存储正则表达式规则
var rules []hostrule

func InitHostRules(filename string) {
	Log.Info("Loading rules from file: ", filename)
	file, err := os.Open(filename)
    if err != nil {
        Log.Fatal("Error opening file:", err)
        return
    }
    defer file.Close()

    

    // 创建文件扫描器
    scanner := bufio.NewScanner(file)
	linecount := 0
    for scanner.Scan() {
		linecount++
		method := "PROXY"
		line_raw := scanner.Text()
        line := strings.TrimSpace(line_raw)

		if line == "[Autoproxy]" {
			continue
		}
        // 跳过注释和空行
        if strings.HasPrefix(line, "!") || line == "" {
            continue
        }
		// log.Println(">>> ", line);

		// DIRECT
		if strings.HasPrefix(line, "@@") {
			method = "DIRECT"
			line = line[2:]
		}
		// REJECT
		if strings.HasSuffix(line, "^$REJECT") {
			method = "REJECT"
			line = line[:len(line)-8]
		}


        if strings.HasPrefix(line, "/") && strings.HasSuffix(line, "/") {
			// 提取正则表达式规则
            pattern := line[1 : len(line)-1]
			rules = append(rules, hostrule{0x00, pattern, method})
        } else if strings.HasPrefix(line, "||") {
			// 允许通配符 * 域名
			pattern := strings.Replace(line[2:], ".", "\\.", -1)
			pattern = strings.Replace(pattern, "*", ".*", -1)
			rules = append(rules, hostrule{0x00, pattern, method})
        } else if _, _, err := net.ParseCIDR(line); err == nil{
			// CIDR IP 段
			rules = append(rules, hostrule{0x01, line, method})
        } else {
			Log.Warn("Invalid rule in line: ", linecount, ": ", line_raw)
			continue
		}
    }

	if err := scanner.Err(); err != nil {
        Log.Fatal("Error reading file:", err)
        return
    }
	Log.Info("Rules: ", rules)
}

// return METHOD: PROXY | DIRECT | REJECT
func Match(host string) (string, error) {
	for _, rule := range rules {
		if rule.typ == 0x00 { // use regex
			re, err := regexp.Compile(rule.pattern)
			if err != nil {
				fmt.Println("Invalid regex pattern:", rule.pattern)
				continue
			}
			if re.MatchString(host) {
				return rule.method, nil
			}
		} else if rule.typ == 0x01 { // use CIDR
			flag, err := isIPInCIDR(host, rule.pattern)
			if err != nil {
				// log.Println(err)
				continue
			}
			if flag {
				return rule.method, nil
			}
		}
	}
	return "PROXY", fmt.Errorf("UNMATCH")
}


func InitProcessRules(filename string) {
	Log.Info("Loading rules from file:", filename)
	file, err := os.Open(filename)
    if err != nil {
        Log.Fatal("Error opening file:", err)
        return
    }
    defer file.Close()

    

    // 创建文件扫描器
    scanner := bufio.NewScanner(file)
	linecount := 0
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        // 跳过注释和空行
        if strings.HasPrefix(line, "#") || line == "" {
			continue
        }
		pattern := ""
		method := ""
		if strings.HasSuffix(line, "PROXY") {
			pattern = line[:len(line)-6]
			method = "PROXY"
		} else if strings.HasSuffix(line, "DIRECT") {
			pattern = line[:len(line)-7]
			method = "DIRECT"
		} else if strings.HasSuffix(line, "REJECT") {
			pattern = line[:len(line)-7]
			method = "REJECT"
		} else {
			Log.Warn("Invalid rule in line: ", linecount, ": ", line)
			continue
		}
		pattern = strings.Replace(pattern, ".", "\\.", -1)
		pattern = strings.Replace(pattern, "*", ".*", -1)
		rules = append(rules, hostrule{0x00, pattern, method})
    }

    if err := scanner.Err(); err != nil {
        Log.Fatal("Error reading file:", err)
        return
    }
	Log.Info("Rules: ", rules)
}