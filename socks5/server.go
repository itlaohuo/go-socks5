package socks5

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
)

type Server interface {
	Run() error
}

type Socks5Server struct {
	Address    string
	Port       int16
	IsServer   bool
	RemoteAddr string
	RemotePort int16
	Config     Config
}

func (s *Socks5Server) String() string {
	return fmt.Sprintf("loacal: %s:%d; remote : %s:%d; %+v ", s.Address, s.Port, s.RemoteAddr, s.RemotePort, s.Config)
}

func (s *Socks5Server) Run() error {
	address := fmt.Sprintf("%s:%d", s.Address, s.Port)
	slog.Info("Socks5Server start ...", "Socks5Server", s)
	listen, err := net.Listen("tcp", address)
	if err != nil {
		slog.Error("start server error", "err", err)
		log.Fatalln("start server error", err)
		return err
	}
	defer listen.Close()
	for {
		clientConn, err := listen.Accept()
		if err != nil {
			slog.Error("start server listen error", "err", err)
			log.Fatalln("start server listen error", err)
			continue
		}
		go func() {
			defer func() {
				if err := recover(); err != nil {
					log.Printf("%v", err)
				}
			}()
			err = s.handleConn(clientConn, &s.Config)
			if err != nil {
				slog.Error("handleConn error", "remoteAddr", clientConn.RemoteAddr(), "err", err)
				return
			}
		}()
	}

}

func (s *Socks5Server) handleConn(conn net.Conn, config *Config) error {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	// 协商
	if err := auth(conn, config, reader); err != nil {
		return err
	}
	// 请求并转发
	return s.request(conn, reader)

}

func NewRequestMessageFromClient(conn io.Reader) (*RequestMessage, error) {
	var buff = make([]byte, 4)
	_, err := conn.Read(buff)
	if err != nil {
		slog.Error("NewRequestMessageFromClient conn.Read(buff) error", "conn", conn)
		return nil, err
	}
	ver := buff[0]
	if ver != Socks5 {
		slog.Error("NewRequestMessageFromClient protocol not supported")
		return nil, errors.New("NewRequestMessageFromClient protocol not supported")
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

	buff := []byte{Socks5, replyType, RSV, AddressTypeIPv4, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(buff)
	return err

}

func NewRequestReplySuccessMessage(conn io.Writer) error {
	// 1  |  1  | X'00' |  1   | Variable |    2
	//TODO  address port :127,0,0,1,0x11,0x39
	buff := []byte{Socks5, ReplySuccess, RSV, AddressTypeIPv4, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(buff)
	return err

}
func NewRequestReplySuccessMessageV2(conn io.Writer, addrAndPortBytes []byte) error {
	// 1  |  1  | X'00' |  1   | Variable |    2
	//TODO  address port :127,0,0,1,0x11,0x39
	buff := []byte{Socks5, ReplySuccess, RSV, AddressTypeIPv4}
	buff = append(buff, addrAndPortBytes...)
	_, err := conn.Write(buff)
	return err

}

// request
func (s *Socks5Server) request(conn io.ReadWriter, reader *bufio.Reader) error {
	// 获取请求信息，处理客户端告知目标地址和Command，即客户端已经告知地址了
	message, err := NewRequestMessageFromClient(reader)
	if err != nil {
		return err
	}
	command := message.Command

	switch command {
	case CommandConnect:
		return s.handleTcp(conn, message)
	case CommandUdpAssociate:
		return handleUdp()
	case CommandBind:
		// ReplyNotSupportedCmd
		NewRequestReplyFailMessage(conn, ReplyNotSupportedCmd)
		return nil
	}
	return nil

}

// handleTcp
func (s5 *Socks5Server) handleTcp(conn io.ReadWriter, message *RequestMessage) error {
	// 作为远程服务端代理进行最终目标请求并转发
	if s5.IsServer {
		tagertAdress := message.Address
		slog.Debug("作为远程服务端代理进行最终目标请求并转发", "tagertAdress", tagertAdress, "Timeout", s5.Config.Timeout)
		targetConn, err := net.DialTimeout("tcp", tagertAdress, s5.Config.Timeout)
		// targetConn, err := net.Dial("tcp", tagertAdress)
		if err != nil {
			// 返回远程网络不可达错误
			slog.Error("net.DialTimeout error", "tagertAdress", tagertAdress, "Timeout", s5.Config.Timeout, "err", err)
			NewRequestReplyFailMessage(conn, ReplyNetworkNotArrived)
			return err
		}
		slog.Debug("作为远程服务端代理请求目标服务器后,给与客户端回复请求成功")
		NewRequestReplySuccessMessage(conn)
		// 数据转发 （协同客户端一起实现）
		// 1 直接复用客户端认证连接进行转发 conn,目前的实现方式
		// 2 TODO  开启端口转发监听 等待客户端连接
		return s5.forward(conn, targetConn)
	}
	return nil

}

// handleUdp
func handleUdp() error {
	log.Printf("TODO implements handleUdp  \n")
	return nil
}

// 转发
func (s5 *Socks5Server) forward(conn io.ReadWriter, dest io.ReadWriteCloser) error {
	defer dest.Close()
	//go io.Copy(dest, conn)
	//_, err := io.Copy(conn, dest)
	//return err
	// 2. 通过启动两个单向数据转发子协程实现双向转发转发
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// dest 内容复制到客户端连接conn
		_, _ = io.Copy(conn, dest)
		cancel()
	}()
	go func() {
		// 等价： 0ioconn.WriteTo(dest).
		_, _ = io.Copy(dest, conn)
		cancel()
	}()

	<-ctx.Done()
	return nil
}
