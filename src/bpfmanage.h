/*
 * 2026-5-7 基于ebpf的win-linux跨平台文件保护程序
 * chawanzhen
*/

#ifndef BPFMANAGE_H
#define BPFMANAGE_H

#define TASK_COMM_LEN 16

#include <iostream>
#include "kernel/kernel.h"
#include <unordered_map>
#include <thread>

namespace bpf {

struct event{
    char comm[TASK_COMM_LEN];//process name
    int success;//1.ture 0.flase;
    uint64_t ts;//time ns
    int op;//1.read 2.write 3.read and write
    uint64_t dev;
    uint64_t inode;
}__attribute__((packed));

struct FileId{
    uint64_t dev;
    uint64_t inode;

    bool operator==(const FileId& other)const{
        return dev == other.dev && inode == other.inode;
    }
    bool operator !=(const FileId& other)const{
        return dev!=other.dev || inode!=other.inode;
    }
}__attribute__((packed));

struct ProcessId{
    uint64_t dev;
    uint64_t inode;

    bool operator ==(const ProcessId& other)const{
        return dev == other.dev && inode == other.inode;
    }
    bool operator !=(const ProcessId& other)const{
        return dev!=other.dev || inode!=other.inode;
    }
}__attribute__((packed));

struct FileIdHash{
    std::size_t operator()(const FileId& id)const{
        std::size_t h1 = std::hash<uint64_t>{}(id.dev);
        std::size_t h2 = std::hash<uint64_t>{}(id.inode);
        return h1 ^ (h2<<1);
    }
};

struct ProcessIdHash{
    std::size_t operator()(const ProcessId& id)const{
        std::size_t h1 = std::hash<uint64_t>{}(id.dev);
        std::size_t h2 = std::hash<uint64_t>{}(id.inode);
        return h1 ^ (h2<<1);
    }
};

class bpfmanage{
public:
    static bpfmanage& instance(){
        static bpfmanage manage;
        return manage;
    }

    bool addProtectFile(const std::string& path);
    bool removeProtectFile(const std::string& path);
    bool addWhiteProcess(const std::string& path);
    bool removeWhiteProcess(const std::string& path);

private:
    bpfmanage(){
        init();
    }
    ~bpfmanage(){cleanUp();}

    bpfmanage(const bpfmanage&) = delete;
    bpfmanage& operator = (const bpfmanage&) = delete;

    bool init();//load only
    void cleanUp();


    struct kernel* skel = nullptr;
    int protected_file_map = -1;
    int white_process_map = -1;
    struct ring_buffer* rb = nullptr;

    static int handleEvent(void* ctx,void* data,size_t data_sz);
    void start_event_loop(struct kernel* skel);
    struct ring_buffer* rb = nullptr;

    std::thread poll_work;

    std::unordered_map<FileId,std::string,FileIdHash>file_protect_path_map;
    std::unordered_map<std::string,FileId>file_protect_id_map;

    std::unordered_map<ProcessId,std::string,ProcessIdHash>white_process_path_map;
    std::unordered_map<std::string,ProcessId>white_process_id_map;
};
}

#endif
