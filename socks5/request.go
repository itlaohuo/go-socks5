package socks5

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

func NewRequestMessage(conn io.Reader) (*RequestMessage, error) {
	var buff = make([]byte, 4)
	_, err := conn.Read(buff)
	if err != nil {
		return nil, err
	}
	ver := buff[0]
	if ver != Socks5 {
		return nil, errors.New("protocol not supported")
	}
	command := buff[1]
	rsv := buff[2]
	addressType := buff[3]
	var address string
	switch addressType {
	case AddressTypeIPv6:
		//return nil, errors.New("AddressTypeIPv6 Not Supported")
		buff = make([]byte, 16)
		_, err = io.ReadFull(conn, buff)
		if err != nil {
			return nil, err
		}
		ip := net.IPAddr{
			IP: buff,
		}
		_, err := io.ReadFull(conn, buff[0:2])
		if err != nil {
			return nil, err
		}
		port := (int16(buff[0]) << 8) + int16(buff[1])
		address = fmt.Sprintf("%s:%d", ip, port)
	case AddressTypeIPv4:
		_, err = io.ReadFull(conn, buff)
		if err != nil {
			return nil, err
		}
		ip := net.IPv4(buff[0], buff[1], buff[2], buff[3]).String()
		_, err := io.ReadFull(conn, buff[0:2])
		if err != nil {
			return nil, err
		}
		port := (int16(buff[0]) << 8) + int16(buff[1])
		address = fmt.Sprintf("%s:%d", ip, port)
	case AddressTypeDomain:
		_, err = io.ReadFull(conn, buff[0:1])
		if err != nil {
			return nil, err
		}
		domainLen := buff[0]
		buff = make([]byte, domainLen)
		io.ReadFull(conn, buff)
		domain := string(buff)
		_, err := io.ReadFull(conn, buff[0:2])
		if err != nil {
			return nil, err
		}
		port := (int16(buff[0]) << 8) + int16(buff[1])
		address = fmt.Sprintf("%s:%d", domain, port)

	}

	requestMessage := RequestMessage{
		Ver:         Socks5,
		Command:     command,
		Rsv:         rsv,
		AddressType: addressType,
		Address:     address,
	}
	return &requestMessage, nil
}

func NewRequestReplyFailMessage(conn io.Writer, replyType ReplyType) error {
	// 1  |  1  | X'00' |  1   | Variable |    2
	//TODO  address port :127,0,0,1,0x11,0x39
	buff := []byte{Socks5, replyType, RSV, AddressTypeIPv4, 127, 0, 0, 1, 0x11, 0x39}
	_, err := conn.Write(buff)
	return err

}

func NewRequestReplySuccessMessage(conn io.Writer) error {
	// 1  |  1  | X'00' |  1   | Variable |    2
	//TODO  address port :127,0,0,1,0x11,0x39
	buff := []byte{Socks5, ReplySuccess, RSV, AddressTypeIPv4, 127, 0, 0, 1, 0x11, 0x39}
	_, err := conn.Write(buff)
	return err

}

// request
func (s *Socks5Server) request(conn io.ReadWriter, reader *bufio.Reader) error {
	// 获取请求信息
	message, err := NewRequestMessage(reader)
	if err != nil {
		return err
	}
	command := message.Command
	//addressType := message.AddressType
	messageAddress := message.Address
	if command == CommandConnect {
		return s.handleTcp(conn, messageAddress)
	} else if command == CommandUdpAssociate {
		return handleUdp()
	} else {
		// ReplyNotSupportedCmd
		NewRequestReplyFailMessage(conn, ReplyNotSupportedCmd)
		return nil
	}

}

// handleTcp
func (s *Socks5Server) handleTcp(conn io.ReadWriter, address string) error {
	targetConn, err := net.DialTimeout("tcp", address, s.Config.Timeout)
	if err != nil {
		NewRequestReplyFailMessage(conn, ReplyCommonFail)
		return err
	}
	//NewAuthReplyMessage()
	NewRequestReplySuccessMessage(conn)
	return forward(conn, targetConn)
}

// handleUdp
func handleUdp() error {
	log.Printf("TODO implements handleUdp  \n")
	return nil
}

// 转发
func forward(conn io.ReadWriter, dest io.ReadWriteCloser) error {
	defer dest.Close()
	//go io.Copy(dest, conn)
	//_, err := io.Copy(conn, dest)
	//return err
	// 2. 通过启动两个单向数据转发子协程实现双向转发转发
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// 等价： 0ioconn.WriteTo(dest).
		_, _ = io.Copy(dest, conn)
		cancel()
	}()
	go func() {
		// dest 内容复制到客户端连接conn
		_, _ = io.Copy(conn, dest)
		cancel()
	}()
	<-ctx.Done()
	return nil
}
