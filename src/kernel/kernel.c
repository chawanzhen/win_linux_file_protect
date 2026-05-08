/*
 * 2026-5-7 基于ebpf的win-linux跨平台文件保护程序
 * chawanzhen
*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define TASK_COMM_LEN 16

#define FMODE_READ      ((unsigned int)0x00000001)//read
#define FMODE_WRITE     ((unsigned int)0x00000002)//write
#define FMODE_EXEC      ((unsigned int)0x00000020)//exec

struct file_id{
  u64 dev;
  u64 inode;
}__attribute__((packed));

struct process_id{
  u64 dev;
  u64 inode;
}__attribute__((packed));

struct event{
  char comm[TASK_COMM_LEN];//process name
  int success;//1.ture 0.flase;
  __u64 ts;//time ns
  int op;//1.read 2.write 3.read and write
  u64 dev;
  u64 inode;
}__attribute__((packed));

struct{
  __uint(type,BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries,256*1024);
}rb SEC(".maps");

struct{
  __uint(type,BPF_MAP_TYPE_HASH);
  __uint(max_entries,1024*1024);
  __type(key,struct file_id);
  __type(value,__u8);
}protected_file SEC(".maps");

struct{
  __uint(type,BPF_MAP_TYPE_BLOOM_FILTER);
  __uint(max_entries,1024*1024);
  __type(value,struct file_id);
}bloom_filter SEC(".maps");

struct{
  __uint(type,BPF_MAP_TYPE_HASH);
  __uint(max_entries,1024*1024);
  __type(key,struct process_id);
  __type(value,__u8);
}whitelist_comm SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(restrict_file_open,struct file* file){
  if(!file || !file->f_inode) return 0;

  //get info
  struct file_id id={0};
  id.dev = BPF_CORE_READ(file->f_inode,i_sb,s_dev);
  id.inode = (u64)BPF_CORE_READ(file->f_inode,i_ino);

  if(bpf_map_peek_elem(&bloom_filter,&id)!=0){
    return 0;
  }

  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  struct process_id exe_id = {0};
  struct file* exe_file = BPF_CORE_READ(task,mm,exe_file);
  if(exe_file){

    exe_id.dev = BPF_CORE_READ(exe_file,f_inode,i_sb,s_dev);
    exe_id.inode = BPF_CORE_READ(exe_file,f_inode,i_ino);
  }

  //get is_white and protected
  __u8* is_protected = bpf_map_lookup_elem(&protected_file,&id);
  if(!is_protected) return 0;
  __u8* is_white = bpf_map_lookup_elem(&whitelist_comm,&exe_id);

  int allowed = is_white ? 1:0;

  //log
  struct event* e;
  e = bpf_ringbuf_reserve(&rb,sizeof(*e),0);
  if(e){
    bpf_get_current_comm(&e->comm,sizeof(e->comm));
    e->success = allowed;
    e->ts = bpf_ktime_get_ns();
    e->op = 0;
    e->dev = id.dev;
    e->inode = id.inode;
    if(file->f_mode & FMODE_READ){
      e->op |= 1;
    }
    if(file->f_mode & FMODE_WRITE){
      e->op |= 2;
    }
    bpf_ringbuf_submit(e,0);
  }
  //return
  if(!allowed){
    return -EPERM;
  }
  return 0;
}
