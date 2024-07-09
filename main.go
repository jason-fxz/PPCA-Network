package main

import (
	"fmt"
	"networking/socks5"
	"os"
)

// 处理不同的命令
func handleCommand(cmd string, args []string) {
	switch cmd {
	case "Server":
		if len(args) != 1 {
			fmt.Println("Usage: Server <listen>")
			return
		}
		listen := args[0]
		socks5.RunServer(listen)
		
	case "Client":
		if len(args) != 2 {
			fmt.Println("Usage: Client <listen> <proxy>")
			return
		}
		listen, proxy := args[0], args[1]
		socks5.Client(listen, proxy)
	case "Rule":
		if len(args) != 3 {
			fmt.Println("Usage: Rule <listen> <proxy> <rulesfile>")
			return
		}
		listen, proxy, rulesFile := args[0], args[1], args[2]
		socks5.ClientWithRule(listen, proxy, rulesFile)
	case "RuleHTTP":
		if len(args) != 3 {
			fmt.Println("Usage: RuleHTTP <listen> <proxy> <rulesfile>")
			return
		}
		listen, proxy, rulesFile := args[0], args[1], args[2]
		socks5.ClientWithHTTPRule(listen, proxy, rulesFile)
	case "RulePID":
		if len(args) != 3 {
			fmt.Println("Usage: RulePID <listen> <proxy> <rulesfile>")
			return
		}
		listen, proxy, rulesFile := args[0], args[1], args[2]
		socks5.ClientWithRuleProcess(listen, proxy, rulesFile)
	case "HTTPaction":
		if len(args) != 3 {
			fmt.Println("Usage: HTTPaction <listen> <proxy> <rulesfile>")
			return
		}
		listen, proxy, rulesFile := args[0], args[1], args[2]
		socks5.HTTPAction(listen, proxy, rulesFile)
	case "Hacker":
		if len(args) != 1 {
			fmt.Println("Usage: Hacker <listen>")
			return
		}
		listen := args[0]
		socks5.Hacker(listen)
	default:
		fmt.Println("Unknown command:", cmd)
	}
}


func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: <command> [arguments...]")
		fmt.Println("Commands:")
		fmt.Println("  Server <listen>")
		fmt.Println("  Client <listen> <proxy>")
		fmt.Println("  Rule <listen> <proxy> <rulesfile>")
		fmt.Println("  RuleHTTP <listen> <proxy> <rulesfile>")
		fmt.Println("  RulePID <listen> <proxy> <rulesfile>")
		fmt.Println("  HTTPaction <listen> <proxy> <rulesfile>")
		fmt.Println("  Hacker <listen>")
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]
	handleCommand(cmd, args)
}
