package socks5

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
)

type Server interface {
	Run() error
}

type Socks5Server struct {
	Address string
	Port    int16
	Config  Config
}

func (s *Socks5Server) Run() error {
	address := fmt.Sprintf("%s:%d", s.Address, s.Port)
	fmt.Printf("Socks5Server start ,address : %s \n", address)
	listen, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalln("start server error", err)
		return err
	}
	defer listen.Close()
	for {
		clientConn, err := listen.Accept()
		if err != nil {
			log.Fatalln("start server listen error", err)
			return err
		}
		go func() {
			defer func() {
				if err := recover(); err != nil {
					log.Printf("%v", err)
				}
			}()
			err = handleConn(clientConn, &s.Config)
			if err != nil {
				log.Printf("handleConn error, remoteAddr %s,%v \n", clientConn.RemoteAddr(), err)
				return
			}
		}()
	}

}

func handleConn(conn net.Conn, config *Config) error {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	// 协商
	err := auth(conn, config, reader)
	if err != nil {
		return err
	}
	// 请求
	targetConn, err := request(conn, reader)
	if err != nil {
		return err
	}
	// 转发
	err = forward(conn, targetConn)
	if err != nil {
		return err
	}
	return nil
}

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
