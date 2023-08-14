package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"socks5server-demo/socks5"
	"strings"
	"time"
)

func main() {

	serverBoolFlag := flag.Bool("server", false, "pls input port")
	portFlag := flag.Int("port", 8080, "pls input port")
	usernameFlag := flag.String("username", "", "pls input username")
	passwdFlag := flag.String("passwd", "", "pls input passwd")
	remoteAddrFlag := flag.String("remoteAddr", "127.0.0.1", "pls input remoteAddr")
	remotePortFlag := flag.Int("remotePort", 10808, "pls input remotePort")
	logLevel := flag.String("logLevel", "INFO", "pls input remotePort")

	// 解析标志参数
	flag.Parse()
	// 修改日志级别
	setSlog(logLevel)
	port := *portFlag
	username := *usernameFlag
	passwd := *passwdFlag
	isServer := *serverBoolFlag
	remoteAddr := *remoteAddrFlag
	remotePort := *remotePortFlag
	address := ""
	// 只支持2种认证方式，默认无需认证，当设置了用户名时需要通过用户名密码认证
	method := socks5.MethodNoAuth
	if username != "" {
		method = socks5.MethodUserPasswd
	}
	if !isServer {
		// 本地客户端代理socks5
		address = "127.0.0.1"
		client := &socks5.Client{
			Addr:       fmt.Sprintf("%s:%d", address, port),
			RemoteAddr: fmt.Sprintf("%s:%d", remoteAddr, remotePort),
			Username:   username,
			Passwd:     passwd,
		}
		slog.Info("start sockes5 clinet (local server) ...", "port", port, "username", username, "passwd", passwd)
		client.Run()
	} else {
		server := &socks5.Socks5Server{
			Address:    address,
			Port:       int16(port),
			IsServer:   isServer,
			RemoteAddr: remoteAddr,
			RemotePort: int16(remotePort),

			Config: socks5.Config{
				Timeout:  30 * time.Second,
				Method:   method,
				Username: username,
				Passwd:   passwd,
				CheckAuthFunc: func(userName, password string) bool {
					return userName == username && password == passwd
				},
			},
		}
		// slog.Debug("start sockes5 server ...", "port", "username", "passwd", "isServer", port, username, passwd, isServer)
		// 正确写法，参数成对依次出现
		slog.Info("start sockes5 server ...", "port", port, "username", username, "passwd", passwd, "isServer", isServer)
		server.Run()
	}

}

// 设置日志属性
func setSlog(logLevel *string) {
	var programLevel = new(slog.LevelVar)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     programLevel,
	}))
	programLevel.Set(slog.LevelInfo)
	slog.SetDefault(logger)

	if logLevel == nil || *logLevel == "" {
		return
	}
	switch strings.ToUpper(*logLevel) {
	case "DEBUG":
		programLevel.Set(slog.LevelDebug)
	case "INFO":
		programLevel.Set(slog.LevelInfo)
	case "WARN":
		programLevel.Set(slog.LevelWarn)
	case "ERROR":
		programLevel.Set(slog.LevelError)
	}
}
