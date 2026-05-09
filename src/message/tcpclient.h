/*
 * 2026-5-8 基于ebpf的win-linux跨平台文件保护程序
 * chawanzhen
*/

#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <string>
#include <thread>
#include <queue>
#include <condition_variable>
#include "message.pb.h"


//消息头
struct MsgHeader{
    uint32_t magic = 0x574C5042; // "WLPB"
    uint32_t op_typel;
    uint32_t length;
}__attribute__((packed));

namespace tcp{

class TcpClient{
public:
    static TcpClient& instance(){
        static TcpClient client;
        return client;
    }

    void startClient(const std::string& ip,int port);
    void stopClient();

    void sendMsg(protocol::OpType type,const google::protobuf::Message& msg);

private:
    TcpClient():_sockfd(-1),_running(false){}

    void connectLoop();    // 负责重连逻辑
    void sendWorker();     // 负责从队列取数据发送
    void recvWorker();     // 负责接收指令并分发
    void heartbeatLoop();  // 负责定时心跳

    int _sockfd;
    std::string _server_ip;
    std::atomic<bool> _running;
    std::atomic<bool>_connected;

    // 发送队列（生产者-消费者）
    struct PendingMsg {
        protocol::OpType type;
        std::string data;
    };
    std::queue<PendingMsg> _send_queue;
    std::mutex _queue_mtx;
    std::condition_variable _cv;

    std::thread _t_connect, _t_send, _t_recv, _t_heartbeat;
};
}

#endif