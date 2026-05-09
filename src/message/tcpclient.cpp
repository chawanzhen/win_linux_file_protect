#include "tcpclient.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include "bpfmanage.h"

using namespace tcp;

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
            std::unique_lock<std::mutex>(_queue_mtx);
            _cv.wait(lock,[this]{return !_send_queue.empty() || !_running});
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
        uint32_t type = ntohl(header.op_type);

        std::vector<char> body(len);
        recv(_sockfd, body.data(), len, MSG_WAITALL);

        // 分发逻辑
        if (type == protocol::ADD_PROTECT_FILE) {
            protocol::CommandRequest req;
            req.ParseFromArray(body.data(), len);
            // 调用 bpfmanage
            bpf::bpfmanage::instance().addProtectFile(req.path());
        }
    }
}