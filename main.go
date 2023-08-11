package main

import (
	"flag"
	"fmt"
	"socks5server-demo/socks5"
	"time"
)

func main() {
	portFlag := flag.Int("port", 10808, "pls input port")
	usernameFlag := flag.String("username", "", "pls input username")
	passwdFlag := flag.String("passwd", "", "pls input passwd")
	// 解析标志参数
	flag.Parse()
	port := *portFlag
	username := *usernameFlag
	passwd := *passwdFlag
	method := socks5.MethodNoAuth
	if username != "" {
		method = socks5.MethodUserPasswd
	}

	server := &socks5.Socks5Server{
		Address: "127.0.0.1",
		Port:    int16(port),
		Config: socks5.Config{
			Timeout: 10 * time.Second,
			Method:  method,
			CheckAuthFunc: func(userName, password string) bool {
				return userName == username && password == passwd
			},
		},
	}
	fmt.Printf("start sockes5 server ... port is %d, username is %s , passwd is %s \n", port, username, passwd)
	server.Run()
}
