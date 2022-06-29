
#include "../include/protocol.h"

Sender::Sender(int sock) : sock(sock){}

ssize_t Sender::send(string msg)
{
    return send(msg.c_str(), msg.size() + 1, APPLICATION_DATA);
}

ssize_t Sender::send(const char *buf, u_short len, u_char msg_type)
{
    char *pos;
    // Content Type
    pos = (char *)mempcpy(_buf, (char *)&msg_type, sizeof(msg_type));

    // Length
    pos = (char *)mempcpy(pos, (char *)&len, sizeof(len));

    // Payload
    pos = (char *)mempcpy(pos, buf, len);

    return write(sock, _buf, pos - _buf);
}

Receiver::Receiver(int sock) : sock(sock){}

ssize_t Receiver::recv(char *buf, u_short &len, u_char &msg_type)
{
    // Content Type
    ret = read(sock, _buf, sizeof(u_char));
    if (ret <= 0)
        return ret;
    msg_type = *(u_char *)_buf;

    // Length
    ret = recv_n_bytes(sizeof(u_short));
    if (ret <= 0)
        return ret;
    len = *(u_short *)_buf;

    // Payload
    ret = recv_n_bytes(buf, len);
    return ret;
}

// read n bytes from sock into _buf
ssize_t Receiver::recv_n_bytes(size_t len)
{
    return recv_n_bytes(_buf, len);
}

ssize_t Receiver::recv_n_bytes(char *buf, size_t len)
{
    ssize_t bytes_read = 0;
    while (bytes_read < (ssize_t)len)
    {
        ret = read(sock, buf + bytes_read, len - bytes_read);
        if (ret <= 0)
            return ret;
        bytes_read += ret;
    }
    return bytes_read;
}