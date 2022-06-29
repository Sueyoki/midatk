#pragma once
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <thread>
#include <future>
#include "protocol.h"
#include "utils.h"
#include <string>
#include <atomic>

#define LEN_BUF 1024
using std::cin;
using std::thread;

class Client
{
public:
    Client();
    Client(int port);
    Client(const char *serverIp);
    Client(const char *serverIp, int port);
    virtual ~Client();

    virtual void init_psk(const char *pskfile);
    const char *getpsk();

    void start();
    int get_sock();
    struct Security_param *get_sp();
    struct sockaddr_in get_server_addr();

    virtual void set_threads_sp(Security_param *sp, bool is_AC, bool is_forward);
    virtual void set_threads_sock(int sock, bool is_AC, bool is_forward);
    static int client_recv(Client *);
    static int client_send(Client *);

protected:
    virtual int deal_appdata_client(char *buf, u_short len_payload, Security_param &sp);

private:
    struct sockaddr_in server_addr;

    // thread *thread_recv, *thread_send;
    std::future<int> fut_recv, fut_send;

    Security_param *sp;
    const char *serverIp;
    const char *pskfile;
    int port;
    int sock;
    ssize_t ret;
    std::atomic<bool> done{false};
    DH dh;
};
