package socks5

import (
	"bytes"
	"log"
	"reflect"
	"testing"
)

func TestSocks5Server_Run(t *testing.T) {

}

func TestNewAuthMessage(t *testing.T) {
	t.Run("test NewAuthMessage should success", func(t *testing.T) {
		buff := []byte{Socks5, MethodUserPasswd, MethodNoAuth, MethodUserPasswd}
		reader := bytes.NewReader(buff)
		message, err := NewAuthMessage(reader)
		if err != nil {
			log.Fatalf("want get err == nil but got err  %s", err)
		}
		wantMessage := AuthMessage{Socks5, MethodUserPasswd, []MethodType{MethodNoAuth, MethodUserPasswd}}
		if !reflect.DeepEqual(*message, wantMessage) {
			log.Fatalf("want get %v but got   %v", wantMessage, message)
		}

	})

	t.Run("test NewAuthMessage should fail", func(t *testing.T) {
		buff := []byte{Socks5, MethodGssApi, MethodNoAuth, MethodUserPasswd}
		reader := bytes.NewReader(buff)
		message, err := NewAuthMessage(reader)
		if err != nil {
			log.Fatalf("want get err == nil but got err  %s", err)
		}
		wantMessage := AuthMessage{Socks5, MethodUserPasswd, []MethodType{MethodNoAuth, MethodUserPasswd}}
		if !reflect.DeepEqual(*message, wantMessage) {
			// 不等是预期的
		} else {
			log.Fatalf("want get %v but got   %v", wantMessage, message)
		}

	})
}
