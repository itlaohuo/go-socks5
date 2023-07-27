package socks5

import (
	"bufio"
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

func request(conn io.ReadWriter, reader *bufio.Reader) (net.Conn, error) {
	message, err := NewRequestMessage(reader)
	if err != nil {
		return nil, err
	}
	command := message.Command
	if command != CommandConnect {
		err := NewRequestReplyFailMessage(conn, ReplyNotSupportedCmd)
		return nil, err
	}
	////addressType := message.AddressType
	address := message.Address
	//
	//NewAuthReplyMessage()
	targetConn, err := net.Dial("tcp", address)
	if err != nil {
		err := NewRequestReplyFailMessage(conn, ReplyCommonFail)
		return nil, err
	}
	log.Println("dial ", address)
	addrValue := targetConn.LocalAddr()
	log.Println(addrValue)
	NewRequestReplySuccessMessage(conn)
	return targetConn, err

}
