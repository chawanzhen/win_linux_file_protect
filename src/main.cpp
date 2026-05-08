/*
 * 2026-5-6 基于ebpf的win-linux跨平台文件保护程序
 * chawanzhen
*/

#include <iostream>
#include "spdlog/spdlog.h"
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/async.h>
#include <memory>
#include <cstdlib>
#include "commit/my_commit.h"

using namespace std;

const char* const G_optstring = "b:c:tdskKf:l:p:h";

bool init_spdlog(std::string log_path){

    try{
        //初始化异步线程池
        spdlog::init_thread_pool(8192,1);

        //创建彩色控制台
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

        console_sink->set_level(spdlog::level::debug);

        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_path, 1024 * 1024 * 5, 3);
        file_sink->set_level(spdlog::level::trace);

        // 组合多个 sink 成一个 logger
        //使用异步工厂 spdlog::async_factory，日志写入在后台线程完成
        auto logger = std::make_shared<spdlog::async_logger>(
            "global_logger",
            spdlog::sinks_init_list{console_sink, file_sink},
            spdlog::thread_pool(),
            spdlog::async_overflow_policy::block);
        logger->set_level(spdlog::level::debug);

        // 设置日志格式：日期 时间 [级别] [文件:行号] 消息文本
        logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%@] %v");

        // 当遇到 error 级别及以上日志时立即刷新磁盘
        logger->flush_on(spdlog::level::err);

        spdlog::set_default_logger(logger);

        return true;
    }catch(const spdlog::spdlog_ex &ex){
        std::cerr << "Spdlog 初始化失败: " << ex.what() << std::endl;
        return false;
    }

    return true;
}

int main(int argc,char* argv[])
{
    const char* const arg0 = argv[0];
    bool log_console =false;
    bool log_file = false;
    std::string log_path("");
    log_path = commit::instance().GetExePath()+"/../log";
    int opt;

    while((opt = getopt(argc,argv,G_optstring))!=-1){
        switch(opt){
        case 'k':
            log_console = true;
            break;
        case 'K':
            log_console = false;
            break;
        case 'l':
            log_file = true;
            log_path = std::string(optarg);
            break;
        default:
            return EXIT_FAILURE;
        }
    }
    if(log_console){
        init_spdlog(log_path);
    }
    return EXIT_SUCCESS;
}
