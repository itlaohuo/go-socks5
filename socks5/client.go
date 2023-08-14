package socks5

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
)

type Client struct {
	Username, Passwd, RemoteAddr, Addr string
}

func (c *Client) Run() {
	listen, err := net.Listen("tcp", c.Addr)
	if err != nil {
		slog.Error("listen failed", "err", err)
		os.Exit(1)
	}
	defer listen.Close()
	for {
		clientConn, err := listen.Accept()
		if err != nil {
			slog.Error("listen.Accept  failed", "err", err)
			continue
		}
		go c.handleClientConn(clientConn)
	}

}

func (c *Client) handleClientConn(clientConn net.Conn) {
	defer clientConn.Close()

	buf := make([]byte, 256)
	n, err := clientConn.Read(buf)
	if err != nil {
		slog.Error("读取客户端请求失败", "err", err)
		return
	}
	// 解析客户端请求（这些字节要再本地服务端消费掉，不能在后续copy中传递）
	if n < 3 || buf[0] != Socks5 || buf[1] != 0x01 || buf[2] != 0x00 {
		slog.Error("无法识别的请求")
		return
	}

	remoteConn, err := net.Dial("tcp", c.RemoteAddr)
	if err != nil {
		slog.Error("连接远程服务端失败", "RemoteAddr", c.RemoteAddr, "err", err)
		return
	}
	defer remoteConn.Close()

	// 请求远程服务端，重新模拟客户端的socks5认证（重点是改写添加密码认证）等，且从远程传过来的认证数据也要在本地服务端消费刁
	if !c.socks5AuthByUserPasswd(remoteConn) {
		slog.Error("远程服务端认证失败", "RemoteAddr", c.RemoteAddr)
		return
	}
	// 给客户端（浏览器）回写不需要认证的回复，本地服务端的回复，浏览器不支持
	_, err = clientConn.Write([]byte{Socks5, MethodNoAuth})
	if err != nil {
		slog.Error("给客户端回写不需要认证失败", "err", err)
		return
	}
	// 伪造的认证阶段结束
	// 后续是流量的正常转发过程，包过socks5的请求阶段
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_, err := io.Copy(remoteConn, clientConn)
		if err != nil {
			slog.Debug("from  clientConn copy to remoteConn failed", "RemoteAddr", c.RemoteAddr, "err", err)
		}
		cancel()
	}()
	go func() {
		_, err = io.Copy(clientConn, remoteConn)
		if err != nil {
			slog.Debug("from  remoteConn copy to clientConn failed", "RemoteAddr", c.RemoteAddr, "err", err)
		}
		cancel()
	}()
	<-ctx.Done()

}

func (c *Client) socks5AuthByUserPasswd(conn net.Conn) bool {
	if c.Username == "" {
		return true
	}
	// socks5认证请求
	_, err := conn.Write([]byte{Socks5, 1, MethodUserPasswd})
	if err != nil {
		slog.Error("发送认证请求失败", "err", err)
		return false
	}
	// 接收soccks5 认证响应
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		slog.Error("读取认证响应失败", "err", err)
		return false
	}
	// 检查认证响应
	if buf[0] != Socks5 || buf[1] != MethodUserPasswd {
		slog.Error("无法进行用户名密码认证")
		return false
	}
	// 客户端发送密码验证数据包 （鉴定协议版本目前为 0x01,UserPasswdAuthVer ）
	// +-----+-----------------+----------+-----------------+----------+
	// | VER | USERNAME_LENGTH | USERNAME | PASSWORD_LENGTH | PASSWORD |
	// +-----+-----------------+----------+-----------------+----------+
	// |   1 |               1 | 1-255    |               1 | 1-255    |
	// +-----+-----------------+----------+-----------------+----------+
	usernameBytes := []byte(c.Username)
	passwdBytes := []byte(c.Passwd)
	var userPassBuff []byte
	userPassBuff = append(userPassBuff, UserPasswdAuthVer)
	userPassBuff = append(userPassBuff, byte(len(usernameBytes)))
	userPassBuff = append(userPassBuff, usernameBytes...)
	userPassBuff = append(userPassBuff, byte(len(passwdBytes)))
	userPassBuff = append(userPassBuff, passwdBytes...)
	_, err = conn.Write(userPassBuff)
	if err != nil {
		slog.Error("用户名密码发送失败")
		return false
	}
	buf = make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		slog.Error("读取用户名密码认证响应失败", "err", err)
		return false
	}
	if buf[0] != UserPasswdAuthVer || buf[1] != UserPasswdAuthSuccess {
		slog.Error("用户名密码认证失败", "err", err)
		return false
	}
	slog.Debug("用户名密码认证成功")
	return true
}
