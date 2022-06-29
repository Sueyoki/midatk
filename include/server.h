
#pragma once
#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <thread>
#include <string>
#include <fstream>
#include "utils.h"
#include "protocol.h"
#include <unordered_map>

#define MAX_CONN_NUM 5
#define LEN_RECV_BUF 1024

using std::cin;
using std::thread;
using std::unordered_map;

class Server
{
public:
    Server();
    Server(int port);
    virtual ~Server();
    
    void start();

    virtual void init_psk(const char *pskfile);
    const char *getpsk();

    int get_sock();

    struct sockaddr_in get_listen_addr();
    
    // Server类未用，用于子类，改变server_recv动作
    virtual void set_threads_sp(Security_param *sp, bool is_AC, bool is_forward);
    virtual void set_threads_sock(int sock, bool is_AC, bool is_forward);

protected:
    // 可用于子类重写，改变server_recv动作
    virtual int deal_appdata_server(char *buf, u_short len_payload, Security_param &sp);

    /// \brief worker functions
    static int task_listen(Server *);
    static int server_recv(Server *);

    // 将线程与和其处理的客户端套接字相绑定
    void bind_thread_sock(thread::id id, int sock);
    
    // 通过线程ID获取与线程绑定的套接字
    int get_sock_by_thread_id(thread::id id);

private:
    int sock; // 服务器套接字
    u_short port; // 服务器端口
    struct sockaddr_in server_addr; // 服务器地址
    const char *pskfile; // PSK密钥文件

    unordered_map<thread::id, int> threads_sock; // 每个接收线程对应的客户端套接字

    DH dh; // Diffile-Hellman类
};