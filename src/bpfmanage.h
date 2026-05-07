/*
 * 2026-5-7 基于ebpf的win-linux跨平台文件保护程序
 * chawanzhen
*/

#ifndef BPFMANAGE_H
#define BPFMANAGE_H

#include <iostream>

namespace bpf {

struct event{
    char comm[TASK_COMM_LEN];//process name
    int success;//1.ture 0.flase;
    u_int64_t ts;//time ns
    int op;//1.read 2.write 3.read and write
    u_int64_t dev;
    u_int64_t inode;
}__attribute__((packed));

struct FileId{
    u_int64_t dev;
    u_int64_t inode;

    bool operator==(const FileId& other)const{
        return dev == other.dev && inode == other.inode;
    }
}__attribute__((packed));

}

#endif
