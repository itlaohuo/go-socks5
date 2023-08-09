package socks5

import (
	"bufio"
	"fmt"
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
			err = s.handleConn(clientConn, &s.Config)
			if err != nil {
				log.Printf("handleConn error, remoteAddr %s,%v \n", clientConn.RemoteAddr(), err)
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
