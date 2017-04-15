#!/bin/bash

# 定义宏DEBUG
# -O3 提供最高级的代码优化
# -lefence   efence即 electric fence，内存调试工具，内存越界或者当访问已经被释放的内存空间时抛出segment fault
gcc -lefence -g -DDEBUG -static -lpthread -pthread -O3 src/*.c -o loader.dbg
