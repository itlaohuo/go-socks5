package main

import (
	"fmt"
	"socks5server-demo/socks5"
	"time"
)

func main() {
	fmt.Println("start sockes5 server ...")
	server := &socks5.Socks5Server{
		Address: "127.0.0.1",
		Port:    int16(8080),
		Config: socks5.Config{
			Timeout: 10 * time.Second,
			Method:  socks5.MethodNoAuth,
			//Method: socks5.MethodUserPasswd,
			//CheckAuthFunc: func(userName, passwd string) bool {
			//	return userName == "admin" && passwd == "123456"
			//},
		},
	}
	server.Run()
}
