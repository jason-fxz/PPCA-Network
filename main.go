package main

import (
	"fmt"
	"networking/socks5"
)

func main() {
	fmt.Println("welcome to jasonfan's socks5 server!")
	fmt.Println(`choose the sub command:

    Server                    -- a socks5 server
    Client                    -- a socks5 client
    Rule                      -- a socks5 client with rules
    RuleHTTP                  -- a socks5 client with rules (get hostname in HTTP request)
    RulePID                   -- a socks5 client with rules (by process name)
    HTTPaction                -- a socks5 client with rules and can modify HTTP request
    Hacker                    -- a socks5 client with rules and can modify TLS request
    `)

	var choice string
	fmt.Scanln(&choice)
startchoice:

	switch choice {
	case "Server":
		socks5.RunServer(":1080")
	case "Client":
		socks5.Client(":1081", ":1080")
	case "Rule":
		socks5.ClientWithRule(":1082", ":7897", "autoproxy.txt")
	case "RuleHTTP":
		socks5.ClientWithHTTPRule(":1082", ":7897", "autoproxy.txt")
	case "RulePID":
		socks5.ClientWithRuleProcess(":1082", ":7897", "processrules.txt")
	case "HTTPaction":
		socks5.HTTPAction(":1082", ":7897", "autoproxy.txt")
	case "Hacker":
		socks5.Hacker(":1082")
	default:
		fmt.Println("Invalid choice")

	}
	goto startchoice
}
