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
	"strings"
)

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

// request
func (s *Socks5Server) request(conn io.ReadWriter, reader *bufio.Reader) error {
	// 获取请求信息
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
		slog.Debug("作为远程服务端代理进行最终目标请求并转发", "tagertAdress", tagertAdress)
		//addressType := message.AddressType
		targetConn, err := net.DialTimeout("tcp", tagertAdress, s5.Config.Timeout)
		if err != nil {
			// 返回远程网络不可达错误才
			slog.Error("net.DialTimeout error", "err", err)
			NewRequestReplyFailMessage(conn, ReplyNetworkNotArrived)
			return err
		}
		NewRequestReplySuccessMessage(conn)
		// 数据转发 （协同客户端一起实现）
		// 1 直接复用客户端认证连接进行转发 conn,目前的实现方式
		// 2 TODO  开启端口转发监听 等待客户端连接
		return s5.forward(conn, targetConn)
	} else {
		// 本地客户端代理，中间需要再次请求远程S5服务器进行转发处理
		slog.Debug("本地客户端代理，中间需要再次请求远程S5服务器进行转发处理")
		remoteConn, err := s5.Dial(conn)
		if err != nil {
			slog.Error("本地客户端代理,s5.Dialfailed", " err", err)
			if remoteConn != nil {
				remoteConn.Close()
			}
			// 返回远程网络不可达错误
			NewRequestReplyFailMessage(conn, ReplyNetworkNotArrived)
			return err
		}

		// 3 客户端告知目标地址(能拿到吗)
		// +----+-----+-------+------+----------+----------+
		// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		// +----+-----+-------+------+----------+----------+
		// | 1  |  1  | X'00' |  1   | Variable |    2     |
		// +----+-----+-------+------+----------+----------+
		addressSlince := strings.Split(message.Address, ":")

		replyBuff := []byte{message.Ver, message.Command, message.Rsv, message.AddressType}
		//DST.ADDR 如果是域名
		if message.AddressType == AddressTypeDomain {
			replyBuff = append(replyBuff, byte(len(addressSlince[0])))
		}
		slog.Debug(fmt.Sprintf("client代理的真实目标地址:%s", message.Address))
		replyBuff = append(replyBuff, []byte(addressSlince[0])...)
		replyBuff = append(replyBuff, []byte(addressSlince[1])...)
		_, err = remoteConn.Write(replyBuff)
		if err != nil {
			errStr := "客户端告知目标地址失败"
			slog.Error(errStr)
			return fmt.Errorf(errStr)
		}
		// 4 远程服务端回复验证
		// +----+-----+-------+------+----------+----------+
		// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		// +----+-----+-------+------+----------+----------+
		// | 1  |  1  | X'00' |  1   | Variable |    2     |
		// +----+-----+-------+------+----------+----------+
		readBuff := []byte{}
		if _, err := io.ReadFull(remoteConn, readBuff); err != nil {
			slog.Error("远程服务端回复验证失败", "err", err)
			return fmt.Errorf("远程服务端回复验证失败 %w ", err)
		}

		slog.Debug("远程服务端回复成功")
		// 本地客户端回复
		NewRequestReplySuccessMessage(conn)
		// 开始传输流量（转发）
		return s5.forward(conn, remoteConn)

	}

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

// ==============  本地客户端向远程Socks5服务器发起连接请求
func (s5 *Socks5Server) Dial(conn io.ReadWriter) (remoteConn net.Conn, err error) {
	var totalBuff [8]byte
	clientMethods := []byte{MethodNoAuth, MethodUserPasswd}

	remoteAdress := fmt.Sprintf("%s:%d", s5.RemoteAddr, s5.RemotePort)
	// TCP 握手
	slog.Debug(fmt.Sprintf("TCP握手remoteAdress %s\n", remoteAdress))
	remoteConn, err = net.DialTimeout("tcp", remoteAdress, s5.Config.Timeout)
	if err != nil {
		slog.Error("TCP握手失败", "err", err)
		return nil, err
	}
	// 1 客户端发送握手包
	// 一、客户端认证请求
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     |  1~255   |
	// +----+----------+----------+
	// 版本

	buff := []byte{Socks5, byte(len(clientMethods))}
	buff = append(buff, clientMethods...)
	if _, err = remoteConn.Write(buff); err != nil {
		remoteConn.Close()
		slog.Error("TCP握手后客户端认证请求失败", "remoteAdress", remoteAdress, "err", err)
		return nil, err
	}

	// 2 服务端响应握手 选择验证方式
	// +-----+--------+
	// | VER | MEHTOD |
	// +-----+--------+
	// |   1 |      1 |
	// +-----+--------+
	readBuff := totalBuff[:2]
	if _, err := io.ReadFull(remoteConn, readBuff); err != nil {
		slog.Error("TCP握手客户端认证请求后，读取响应失败", "remoteAdress", remoteAdress, "err", err)
		return remoteConn, fmt.Errorf("remote response read full failed %w ", err)
	}
	remoteSocketVer := readBuff[0]
	remoteMethodChoose := readBuff[1]
	if remoteSocketVer != Socks5 {
		slog.Error("TCP握手客户端认证请求后，remote server socks version not supported", "remoteAdress", remoteAdress, "err", err)
		return remoteConn, errors.New("remote server socks version not supported")
	}

	// 进一步认证（如果需要用户名密码，不需要直接返回）
	err = s5.clientAuth(remoteConn, remoteMethodChoose)
	slog.Debug("全部认证成功")
	return remoteConn, err

}
