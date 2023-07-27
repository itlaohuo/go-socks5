package socks5

// AuthMessage
//VER	NMETHODS	METHODS
//1		1			1 to 255
type AuthMessage struct {
	Ver      byte
	NMethods byte
	Methods  []MethodType
}

// AuthReplyMessage
//VER	METHOD
//1		1
type AuthReplyMessage struct {
	Ver    byte
	Method MethodType
}

// UserPasswdAuthMessage
//----+------+----------+------+----------+
//|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//+----+------+----------+------+----------+
//| 1  |  1   | 1 to 255 |  1   | 1 to 255
type UserPasswdAuthMessage struct {
	Ver         byte
	UserNameLen byte
	UserName    string
	PasswdLen   byte
	Passwd      string
}

// RequestMessage
//VER	CMD	RSV		ATYP	DST.ADDR	DST.PROT
//1		1	X’00’	1		Variable	2
type RequestMessage struct {
	//VER	CMD	RSV	ATYP	DST.ADDR	DST.PROT
	Ver         byte
	Command     CommandType
	Rsv         byte
	AddressType byte
	Address     string
	Port        int16
}

// ReplyMessage
//VER	REP		RSV			ATYP	BND.ADDR	BND.PORT
//1		1		X’00’		1		Variable	2
type ReplyMessage struct {
	Ver         byte
	Reply       ReplyType
	Rsv         byte
	AddressType byte
	Address     string
	Port        int16
}
