package socks5

import "time"

const (
	Socks5                byte       = 0x05
	UserPasswdAuthVer     byte       = 0x01
	UserPasswdAuthSuccess byte       = 0x00
	UserPasswdAuthFail    byte       = 0x01
	VerLen                byte       = 1
	NMethodLen            byte       = 1
	MethodNoAuth          MethodType = 0x00
	MethodGssApi          MethodType = 0x01
	MethodUserPasswd      MethodType = 0x02
	MethodNotSupported    MethodType = 0xff

	// 客户端发送请求报文 DST.PORT 以网络字节顺序出现的端口号
	//VER	CMD		RSV	  	  ATYP	DST.ADDR	DST.PROT
	//1		1		X’00’	 	1	Variable	2

	RSV           byte = 0x00
	RequestCmdLen byte = 1
	PortLen       byte = 2

	CommandConnect      CommandType = 1
	CommandBind         CommandType = 2
	CommandUdpAssociate CommandType = 3
	// AddressTypeIPv4 基于IPV4的IP地址，4个字节长
	AddressTypeIPv4 AddressType = 0x01
	// AddressTypeDomain 基于域名的地址，地址字段中的第一字节是以字节为单位的该域名的长度，没有结尾的NUL字节。
	AddressTypeDomain AddressType = 0x03
	// AddressTypeIPv6 基于IPV4的IP地址，16个字节长
	AddressTypeIPv6 AddressType = 0x04

	// REPLY 应答,服务器返回给客户端
	//VER		REP		RSV		ATYP	BND.ADDR	BND.PORT
	//1		    1		X’00’	1		Variable	2

	ReplySuccess                 ReplyType = 0x00
	ReplyCommonFail              ReplyType = 0x01
	ReplyRegularDenied           ReplyType = 0x02
	ReplyNetworkNotArrived       ReplyType = 0x03
	ReplyHostNotArrived          ReplyType = 0x04
	ReplyConnectionDenied        ReplyType = 0x05
	ReplyTSLTimeout              ReplyType = 0x06
	ReplyNotSupportedCmd         ReplyType = 0x07
	ReplyNotSupportedAddressType ReplyType = 0x08
	ReplyNotDefined              ReplyType = 0x09
)

type MethodType = byte
type AddressType = byte
type ReplyType = byte
type CommandType = byte

type Config struct {
	Method        MethodType
	CheckAuthFunc func(userName string, passwd string) bool
	Timeout       time.Duration
}
