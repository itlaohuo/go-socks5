package socks5

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
)

// NewAuthMessageFromClient 从连接中获取协商认证信息
func NewAuthMessageFromClient(conn io.Reader) (*AuthMessage, error) {
	var buff = make([]byte, VerLen+NMethodLen)
	_, err := io.ReadFull(conn, buff)
	if err != nil {
		return nil, err
	}
	ver := buff[0]
	if ver != Socks5 {
		slog.Error("NewAuthMessageFromClient protocol not supported")
		return nil, errors.New("NewAuthMessageFromClient protocol not supported")
	}
	nMethods := buff[1]
	buff = make([]byte, nMethods)
	_, err = io.ReadFull(conn, buff)
	methods := buff[:]
	if err != nil {
		slog.Error("ReadFull from conn failed", "err", err)
		return nil, err
	}
	authMessage := AuthMessage{Ver: Socks5, NMethods: nMethods, Methods: methods}
	return &authMessage, nil
}

// ServerChooseOneSupportedMethodToClient 协商认证回复
func ServerChooseOneSupportedMethodToClient(conn io.Writer, method MethodType) error {
	buff := []byte{Socks5, method}
	_, err := conn.Write(buff)
	return err

}

// NewUserPasswdMessage 从连接中获取账号密码
func NewUserPasswdMessage(conn io.Reader) (*UserPasswdAuthMessage, error) {
	var buff = make([]byte, 2)
	_, err := io.ReadFull(conn, buff)
	if err != nil {
		return nil, err
	}
	ver := buff[0]
	slog.Debug("=====NewUserPasswdMessage ver =====", "ver", buff[0])
	if ver != UserPasswdAuthVer {
		return nil, errors.New("NewUserPasswdMessage ver not supported")
	}
	userLen := buff[1]
	buff = make([]byte, userLen+1)
	_, err = io.ReadFull(conn, buff)
	if err != nil {
		return nil, err
	}
	userName := string(buff[0:userLen])
	passwdLen := buff[userLen]
	buff = make([]byte, passwdLen)
	_, err = io.ReadFull(conn, buff[0:passwdLen])
	if err != nil {
		return nil, err
	}
	passwd := string(buff[0:passwdLen])
	userPasswdAuthMessage := UserPasswdAuthMessage{
		Ver: UserPasswdAuthVer, UserNameLen: userLen, UserName: userName, Passwd: passwd,
	}
	return &userPasswdAuthMessage, nil
}

// NewUserPasswdReplyMessage 回复账号密码认证结果
func NewUserPasswdReplyMessage(conn io.Writer, status byte) error {
	buff := []byte{UserPasswdAuthVer, status}
	_, err := conn.Write(buff)
	return err

}

// 协商认证
func auth(conn net.Conn, config *Config, reader *bufio.Reader) error {
	authMessage, err := NewAuthMessageFromClient(reader)
	if err != nil {
		return err
	}
	if authMessage != nil {
		supportedMethod := bytes.IndexByte(authMessage.Methods, config.Method) >= 0
		if !supportedMethod {
			// Server选择一个自己也支持的认证方案
			ServerChooseOneSupportedMethodToClient(conn, MethodNotSupported)
			return err
		}
		// Server选择一个自己也支持的认证方案
		err := ServerChooseOneSupportedMethodToClient(conn, config.Method)
		if err != nil {
			return err
		}
		//子协商
		if config.Method == MethodUserPasswd {
			userPasswdAuthMessage, err := NewUserPasswdMessage(conn)
			if err != nil {
				return err
			}
			userName := userPasswdAuthMessage.UserName
			passwd := userPasswdAuthMessage.Passwd
			passed := config.CheckAuthFunc(userName, passwd)
			if !passed {
				NewUserPasswdReplyMessage(conn, UserPasswdAuthFail)
			} else {
				NewUserPasswdReplyMessage(conn, UserPasswdAuthSuccess)
			}

		}
	}
	return err
}

// 选择认证方式并认证
func (s5 *Socks5Server) clientAuth(conn io.ReadWriter, method MethodType) (err error) {
	if method == MethodNoAuth {
		slog.Debug("MethodNoAuth clinet auth success")
		return nil
	}
	if method != MethodUserPasswd {
		slog.Error("auth not supported method")
		return errors.New("not supported method")
	}
	var totalBuff [8]byte
	// 客户端发送验证数据包 （鉴定协议版本目前为 0x01 ）
	// +-----+-----------------+----------+-----------------+----------+
	// | VER | USERNAME_LENGTH | USERNAME | PASSWORD_LENGTH | PASSWORD |
	// +-----+-----------------+----------+-----------------+----------+
	// |   1 |               1 | 1-255    |               1 | 1-255    |
	// +-----+-----------------+----------+-----------------+----------+

	var buff []byte
	// 版本
	buff = append(buff, UserPasswdAuthVer)
	buff = append(buff, byte(len(s5.Config.Username)))
	buff = append(buff, []byte(s5.Config.Username)...)
	buff = append(buff, byte(len(s5.Config.Passwd)))
	buff = append(buff, []byte(s5.Config.Passwd)...)
	if _, err = conn.Write(buff); err != nil {
		slog.Error("auth write failed")
		return fmt.Errorf("<auth write err> %w ", err)
	}

	// 服务端响应验证包
	// +-----+--------+
	// | VER | STATUS |
	// +-----+--------+
	// |   1 |      1 |
	// +-----+--------+
	readBuff := totalBuff[:2]
	if _, err = io.ReadFull(conn, readBuff); err != nil {
		slog.Error("auth readFull failed")
		return errors.New("<auth readFull failed>")
	}

	// 认证失败
	if readBuff[1] != ReplySuccess {
		slog.Error("auth failed")
		return errors.New("<auth failed>")
	}
	slog.Debug("clinet auth success")
	return nil

}
