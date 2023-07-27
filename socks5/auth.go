package socks5

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
)

// NewAuthMessage 从连接中获取协商认证信息
func NewAuthMessage(conn io.Reader) (*AuthMessage, error) {
	var buff = make([]byte, VerLen+NMethodLen)
	_, err := io.ReadFull(conn, buff)
	if err != nil {
		return nil, err
	}
	ver := buff[0]
	if ver != Socks5 {
		return nil, errors.New("protocol not supported")
	}
	nMethods := buff[1]
	buff = make([]byte, nMethods)
	_, err = io.ReadFull(conn, buff)
	methods := buff[:]
	if err != nil {
		return nil, err
	}
	authMessage := AuthMessage{Ver: Socks5, NMethods: nMethods, Methods: methods}
	return &authMessage, nil
}

// NewAuthReplyMessage 协商认证回复
func NewAuthReplyMessage(conn io.Writer, method MethodType) error {
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
	if ver != UserPasswdAuthVer {
		return nil, errors.New("ver not supported")
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
	authMessage, err := NewAuthMessage(reader)
	if err != nil {
		return err
	}
	if authMessage != nil {
		supportedMethod := bytes.IndexByte(authMessage.Methods, config.Method) >= 0
		if !supportedMethod {
			NewAuthReplyMessage(conn, MethodNotSupported)
			return err
		}
		err := NewAuthReplyMessage(conn, config.Method)
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
			}
			NewUserPasswdReplyMessage(conn, UserPasswdAuthSuccess)
		}
	}
	return err
}
