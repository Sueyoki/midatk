

/*
 * The mid server is for man in the middle attack, 
 * to perform the attack, you should redirect the client's data packet
 * to the mid server using ARP spoofing, DNS spoofing etc. 
 * The mid server has two parts, one for the client(running a fake server)
 * and the other for the server (running a fake client). 
 * 
 *                     +------------------------+
 *                     |                        |
 * (client)A <-------> | Server     C    Client | <-------> B(Server)
 *                     |                        |
 *                     +------------------------+ 
 * 
 * To crack the diffie hellman key exchange algorithm, we should establish two
 * connections, so we can consult two shared keys, decode and forwarding data. 
 * 
 * There are basically two kind of threads in the mid server, one is called forward thread
 * and the other is called backward thread. The forward thread accepts data from the
 * client and forward it to the server while the backward thread receives data from 
 * the server and forward backward to the client. 
 * Each threads will use the key between A and C and the key between C and B, which is called
 * Security param spA_C and spC_B to decrypt the 'Application Data'. 
*/


#pragma once
#include "server.h"
#include "client.h"

class MidServer : public Server, public Client
{
public:
    MidServer();
    MidServer(int port);
    MidServer(const char *serverIp);
    MidServer(const char *serverIp, int port);

    ~MidServer();

    void start();

    void set_thread_forward(thread* t);
    void set_thread_backward(thread *t);
    
    // init pskfile of the server and of the client simultaneously
    void init_psk(const char* pskfile) override;

    thread *get_thread_forward();
    thread *get_thread_backward();

protected:
    // deal with client A <--> C overrides the function in class Server
    virtual int deal_appdata_server(char *buf, u_short len_payload, Security_param &sp) override;

    // deal with server C <--> B overrides the function in class Client
    virtual int deal_appdata_client(char *buf, u_short len_payload, Security_param &sp) override;

    // bind the forward thread and the corresponding backward thread
    void bind_threads(thread::id f, thread::id b);

    // set the security param according to the thread type and which side it deals with
    virtual void set_threads_sp(Security_param *sp, bool is_AC, bool is_forward) override;

    // set the sock according to the thread type and which side it deals with
    virtual void set_threads_sock(int sock, bool is_AC, bool is_forward) override;

private:
    // mid server listen func
    static int task_listen(MidServer *self);

    // map from forward thread to backward thread
    unordered_map<thread::id, thread::id> thread_fb;

    // map from backward thread to forward thread
    unordered_map<thread::id, thread::id> thread_bf;

    // map the current thread id to the security param at the A_C side
    unordered_map<thread::id, Security_param *> thread_spA_C;

    // map the current thread id to the security param at the C_B side
    unordered_map<thread::id, Security_param *> thread_spC_B;

    // map the current thread id to the socket at the A_C side
    unordered_map<thread::id, int> thread_sockA_C;

    // map the current thread id to the socket at the C_B side
    unordered_map<thread::id, int> thread_sockC_B;
    
    // the thread dealing with forwarding data A -> C -> B
    thread *thread_forward;

    // the thread dealing with backwarding data B -> C -> A
    thread *thread_backward;
};