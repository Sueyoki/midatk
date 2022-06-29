
#pragma once
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <string>
#include "msg_type.h"
#include "lengths.h"

// buffer size
#define LEN_SENDER_BUF      1024
#define LEN_RECIEVER_BUF    1024

using std::string;

#ifndef USE_DEFAULT_GPQ
struct DH_hdr
{
    u_short len_P = LEN_MODULE;
    u_char P[LEN_MODULE];
    u_short len_g = LEN_GENERATOR;
    u_char g[LEN_GENERATOR];
};
#endif

struct Key_change_hdr
{
    u_short len_pubkey = LEN_PUBLIC_KEY;
    u_char pubkey[LEN_PUBLIC_KEY];
};

struct HandShake_hdr
{
    u_char type;
    u_short len;
    u_char rand[32];
};

struct appData_hdr
{
    // 数据包序号
    u_long seq_no;
    // 可扩展数据部分
    u_char data[];
};

class Sender
{
public:
    Sender(int sock);
    ssize_t send(const char *buf, u_short len, u_char msg_type);
    ssize_t send(string msg);

private:
    char _buf[LEN_SENDER_BUF];
    int sock;
    ssize_t ret;
};

class Receiver
{
public:
    Receiver(int sock);
    ssize_t recv(char *buf, u_short &len, u_char &msg_type);

private:
    char _buf[LEN_RECIEVER_BUF];
    int sock;
    ssize_t ret;

    ssize_t recv_n_bytes(size_t len);
    ssize_t recv_n_bytes(char* buf, size_t len);
};
