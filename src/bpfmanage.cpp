#include "bpfmanage.h"
#include "spdlog/spdlog.h"
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <string>
#include <csignal>
#include <bpf/bpf.h>

using namespace bpf;

#define MAX_PATH 256

//libbpf
static int my_libbpf_print(enum libbpf_print_level level,const char* format,va_list args){
    return vfprintf(stderr,format,args);
}

std::atomic<bool> g_stop_poll(false);

bool bpfmanage::init(){
    libbpf_set_print(my_libbpf_print);

    //load skel
    skel = kernel__open_and_load();
    if(!skel){
        spdlog::error("kernel加载失败");
        return false;
    }

    //add lsm
    int err = kernel__attach(skel);
    if(err){
        spdlog::error("lsm attach 失败");
        delete skel;
        return false;
    }

    //get map
    protected_file_map = bpf_map__fd(skel->maps.protected_file);
    white_process_map = bpf_map__fd(skel->maps.whitelist_comm);
    if(protected_file_map<0 || white_process_map<0){
        spdlog::error("获取map失败");
        cleanUp();
        return false;
    }

    return true;
}

void bpfmanage::cleanUp(){
    g_stop_poll.store(true);
    if (poll_work.joinable()) poll_work.join();
    if (skel) {
        kernel__destroy(skel);
    }
    if(rb){
        ring_buffer__free(rb);
    }
    protected_file_map = -1;
    white_process_map = -1;
}

bool bpfmanage::addProtectFile(const std::string &path){
    if(protected_file_map<0 || path.empty()){
        return false;
    }

    struct stat st;
    if(stat(path.c_str(),&st)!=0) {
        spdlog::error("获取stat失败：{}",path);
        return false;
    }

    struct FileId id;
    memset(&id,0,sizeof(id));

    id.dev = (uint64_t)st.st_dev;
    id.inode = (uint64_t)st.st_ino;

    if(file_protect_id_map.count(path)){
        FileId oldId = file_protect_id_map[path];
        if(oldId!=id){
            file_protect_id_map[path]=id;
            file_protect_path_map.erase(oldId);
            file_protect_path_map[id]=path;
        }else return true;
    }

    uint8_t value = 1;

    int res = bpf_map_update_elem(protected_file_map,&id,&value,BPF_ANY);

    if(res == 0){
        file_protect_id_map[path]=id;
        file_protect_path_map[id]=path;
        return true;
    }else{
        spdlog::error("添加：{} 失败",path);
    }
    return false;
}

bool bpfmanage::removeProtectFile(const std::string &path){
    if(protected_file_map<0 || path.empty()) return false;

    struct stat st;
    if(stat(path.c_str(),&st)!=0) {
        spdlog::error("获取stat失败：{}",path);
        return false;
    }

    struct FileId id;
    memset(&id,0,sizeof(id));

    id.dev = (uint64_t)st.st_dev;
    id.inode = (uint64_t)st.st_ino;

    int res = bpf_map_delete_elem(protected_file_map,&id);

    file_protect_id_map.erase(path);
    file_protect_path_map.erase(id);
    if(res==0) return true;
    else{
        spdlog::error("移除：{} 失败",path);
    }
    return false;
}

bool bpfmanage::addWhiteProcess(const std::string &path){
    if(white_process_map<0 || path.empty()) return false;

    struct stat st;
    if(stat(path.c_str(),&st)!=0) {
        spdlog::error("获取stat失败：{}",path);
        return false;
    }

    struct ProcessId id;
    memset(&id,0,sizeof(id));

    id.dev = st.st_dev;
    id.inode = st.st_ino;

    if(white_process_id_map.count(path)){
        ProcessId oldId = white_process_id_map[path];
        if(oldId!=id){
            white_process_id_map[path]=id;
            white_process_path_map.erase(oldId);
            white_process_path_map[id]=path;
        }else return true;
    }
    uint8_t value = 1;
    int res = bpf_map_update_elem(white_process_map,&id,&value,BPF_ANY);
    if(res==0){
        white_process_id_map[path]=id;
        white_process_path_map[id]=path;
        return true;
    }else{
        spdlog::error("添加白名单程序: {} 失败",path);
    }
    return false;
}

bool bpfmanage::removeWhiteProcess(const std::string &path){
    if(white_process_map<0 || path.empty()) return false;

    struct stat st;
    if(stat(path.c_str(),&st)!=0) {
        spdlog::error("获取stat失败：{}",path);
        return false;
    }

    struct ProcessId id;
    memset(&id,0,sizeof(id));

    id.dev = st.st_dev;
    id.inode = st.st_ino;

    int res = bpf_map_delete_elem(white_process_map,&id);
    white_process_id_map.erase(path);
    white_process_path_map.erase(id);
    if(res) return true;
    else{
        spdlog::error("删除白名单: {} 失败",path);
    }
    return false;
}

int bpfmanage::handleEvent(void *ctx, void *data, size_t data_sz){
    if(data_sz<sizeof(struct event)){
        spdlog::error("接受内核信息大小有误");
        return 0;
    }

    auto* self = static_cast<bpfmanage*>(ctx);
    auto* e = static_cast<struct event*>(data);
    struct FileId id;
    id.inode = e->inode;
    id.dev = e->dev;
    std::string visit_process_path(e->comm);
    std::string visit_file_path = self->file_protect_path_map[id];
    std::string opt;
    if(e->op==1) opt = "READ";
    else if(e->op==2) opt = "WRITE";
    else if(e->op==3) opt = "READ/WRITE";
    else opt = "UNKNOW";

    std::string visit_result = e->success == 1 ? "成功" : "失败";
    spdlog::info("程序: {} 尝试访问: {} {}",visit_process_path,visit_file_path,visit_result);
    return false;
}

void bpf_poll_thread_func(struct ring_buffer* rb) {

    while (!g_stop_poll.load()) {
        int err = ring_buffer__poll(rb, 100);

        if (err == -EINTR) {
            continue;
        }
        if (err < 0) {
            spdlog::error("RingBuffer 轮询出错: {}", err);
            break;
        }
    }

    spdlog::info("eBPF 轮询线程正在退出...");
}

void bpfmanage::start_event_loop(kernel *skel){
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),handleEvent,this,nullptr);
    if(!rb){
        spdlog::error("无法创建 RingBuffer 管理器");
        return ;
    }

    poll_work = std::thread(bpf_poll_thread_func,rb);
}