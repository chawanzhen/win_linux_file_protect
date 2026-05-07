/*
 * 2026-5-7 基于ebpf的win-linux跨平台文件保护程序
 * chawanzhen
*/

#include <iostream>

class commit{
public:
    commit& instance(){
        static commit com;
        return com;
    }

private:
    commit();
    ~commit();

    std::string GetExePath();
};