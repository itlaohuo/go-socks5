package socks5

import (
	"bufio"
	"fmt"
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
