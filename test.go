// Go 时间格式化示例
// 使用 time 包中的 Format 方法进行时间格式化
// Go 使用特定的时间（2006年1月2日 15时04分05秒 MST）来表示时间格式

package main

import (
	"fmt"
	"time"
)

func main() {
    // 获取当前时间
    currentTime := time.Now()

    // 格式化为 YYYY-MM-DD
    fmt.Println("当前日期:", currentTime.Format("2006-01-02"))

    // 格式化为 YYYY-MM-DD HH:mm:ss
    fmt.Println("当前时间:", currentTime.Format("2006-01-02_15:04:05"))

    // 格式化为 YYYY年MM月DD日 HH时mm分ss秒
    fmt.Println("中文格式化时间:", currentTime.Format("2006年01月02日 15时04分05秒"))

    // 使用预定义格式
    fmt.Println("RFC1123格式:", currentTime.Format(time.RFC1123))
}