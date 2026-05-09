#include "tcpclient.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include "bpfmanage.h"
#include <unistd.h>
#include <spdlog/spdlog.h>

using namespace tcp;

void TcpClient::startClient(const std::string &ip, int port){
    _sockfd = socket(AF_INET,SOCK_STREAM,0);
    if(_sockfd==-1){
        spdlog::error("socketfd 创建失败");
        return ;
    }

    struct sockaddr_in server_addr;
    std::memset(&server_addr,0,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if(inet_pton(AF_INET,ip.c_str(),&server_addr.sin_addr)<0){
        close(_sockfd);
        _sockfd = -1;
        spdlog::error("无效的ip地址");
        return ;
    }

    if(connect(_sockfd,(struct sockaddr*)&server_addr,sizeof(server_addr))==-1){
        close(_sockfd);
        _sockfd = -1;
        spdlog::error("连接失败");
        return ;
    }
    spdlog::debug("连接到:{} 成功",ip);
}

void TcpClient::stopClient(){
    close(_sockfd);
    _sockfd = -1;
    return ;
}

void TcpClient::sendMsg(protocol::OpType type, const google::protobuf::Message &msg){
    PendingMsg pm;
    pm.type = type;
    msg.SerializePartialToString(&pm.data);

    {
        std::lock_guard<std::mutex>lock(_queue_mtx);
        _send_queue.push(std::move(pm));
    }
    _cv.notify_one();
}

void TcpClient::sendWorker(){
    while(_running){
        PendingMsg pm;
        {
            std::unique_lock<std::mutex>lock(_queue_mtx);
            _cv.wait(lock,[this]{return !_send_queue.empty() || !_running ;});
            if(!_running) break;
            pm = std::move(_send_queue.front());
            _send_queue.pop();
        }

        if(!_connected) continue;

        //构建Header
        MsgHeader header;
        header.op_typel = htonl(static_cast<uint32_t>(pm.type));
        header.length = htonl(pm.data.size());

        if(write(_sockfd,&header,sizeof(header))<=0 ||
            write(_sockfd,pm.data.data(),pm.data.size())<=0
            ){
            _connected = false;
        }
    }
}

void TcpClient::recvWorker() {
    while (_running) {
        if (!_connected) { sleep(1); continue; }

        MsgHeader header;
        int n = recv(_sockfd, &header, sizeof(header), MSG_WAITALL);
        if (n <= 0) { _connected = false; continue; }

        uint32_t len = ntohl(header.length);
        uint32_t type = ntohl(header.op_typel);

        std::vector<char> body(len);
        recv(_sockfd, body.data(), len, MSG_WAITALL);

        // 分发逻辑
        if (type == protocol::ADD_PROTECT_FILE) {
            protocol::FileRequest req;
            req.ParseFromArray(body.data(), len);
            // 调用 bpfmanage
            bpf::bpfmanage::instance().addProtectFile(req.path());
        }
    }
}