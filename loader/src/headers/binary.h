#pragma once

#include "includes.h"

#define BINARY_BYTES_PER_ECHOLINE   128

struct binary {
    char arch[6];//体系架构
    int hex_payloads_len;//payload的长度
    char **hex_payloads;//payload
};

//将所有bin文件读入binary结构体中,结构体数组
BOOL binary_init(void);
struct binary *binary_get_by_arch(char *arch);

static BOOL load(struct binary *bin, char *fname);
