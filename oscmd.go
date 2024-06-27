package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

func getPIDByPortWindows(port string) (string, error) {
    // 执行 netstat 命令并获取输出
    cmd := exec.Command("netstat", "-ano")
    output, err := cmd.Output()
    if err != nil {
        return "", err
    }

    // 解析输出并找到对应端口的 PID
    lines := strings.Split(string(output), "\r\n")
    for _, line := range lines {
        words := strings.Fields(line)
        if len(words) >= 2 && strings.Contains(words[1], ":"+port) {
            fields := strings.Fields(line)
            if len(fields) >= 5 {
                pid := fields[4]
                return pid, nil
            }
        }
    }
    return "", fmt.Errorf("no process found on port %s", port)
}

func getProcessNameByPIDWindows(pid string) (string, error) {
    // 执行 tasklist 命令并获取输出
    cmd := exec.Command("tasklist", "/FI", "PID eq "+pid)
    output, err := cmd.Output()
    if err != nil {
        return "", err
    }

    // 解析输出并找到对应 PID 的进程名称
    lines := strings.Split(string(output), "\n")
    if len(lines) > 3 {
        fields := strings.Fields(lines[3])
        if len(fields) > 0 {
            return fields[0], nil
        }
    }
    return "", fmt.Errorf("no process name found for PID %s", pid)
}


func getProcessByPortWindows(port string) (name string, pid string, err error) {
    pid, err = getPIDByPortWindows(port)
    if err != nil {
        return "", "", err
    }
    name, err = getProcessNameByPIDWindows(pid)
    if err != nil {
        return "", "", err
    }
    return
}

func GetProcessByPort(port string) (name string, pid string, err error) {
    if strings.HasPrefix(runtime.GOOS, "windows") {
        return getProcessByPortWindows(port)
    }
    return "", "", fmt.Errorf("unsupported platform %s", runtime.GOOS)
}


// func main() {
//     port := "7897"
//     name, pid, err:= GetProcessByPort(port)
//     if err != nil {
//         log.Println(err)
//     }
//     fmt.Printf("Process on port %s: PID %s, Name %s\n", port, pid, name)
// }