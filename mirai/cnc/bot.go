package main

import (
    "net"
    "time"
)

type Bot struct {
    uid     int
    conn    net.Conn
    version byte
    source  string
}

//解析命令    source....
func NewBot(conn net.Conn, version byte, source string) *Bot {
    return &Bot{-1, conn, version, source}
}

func (this *Bot) Handle() {
    clientList.AddClient(this)  //添加client
    defer clientList.DelClient(this)

    buf := make([]byte, 2)  //这应该是接收心跳包
    for {
        this.conn.SetDeadline(time.Now().Add(180 * time.Second))
        if n,err := this.conn.Read(buf); err != nil || n != len(buf) {
            return
        }
        //为啥还要回应
        if n,err := this.conn.Write(buf); err != nil || n != len(buf) {
            return
        }
    }
}

func (this *Bot) QueueBuf(buf []byte) {
    this.conn.Write(buf)
}
