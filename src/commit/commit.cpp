#include "commit.h"
#include <unistd.h>
#include <limits.h>

commit::commit(){}

commit::~commit(){}

//返回当前可执行文件所在目录绝对路径
std::string commit::GetExePath(){
    char abs_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe",abs_path,PATH_MAX-1);
    if(len!=-1){
        std::string path(abs_path,len);
        size_t last_pos = path.find_last_of('/');
        if(last_pos!=std::string::npos){
            return path.substr(0,last_pos);
        }
    }
    return "";
}
