
#include "../include/mid_server.h"

MidServer::MidServer() : Server(20411), Client(20410) {}

MidServer::MidServer(int port) : Server(port), Client(port) {}

MidServer::MidServer(const char *serverIp) : Server(20411), Client(serverIp, 20410) {}

MidServer::MidServer(const char *serverIp, int port) : Server(port), Client(serverIp, port) {}

MidServer::~MidServer() {}

void MidServer::start()
{
    int ret = listen(Server::get_sock(), MAX_CONN_NUM);

    if (ret == -1)
    {
        cerr << "listen failed" << endl;
        return;
    }

    thread thread_listen(task_listen, this);

    thread_listen.detach();

    cout << "MidServer started listening at " << inet_ntoa(Server::get_listen_addr().sin_addr) << ":" << ntohs(Server::get_listen_addr().sin_port) << endl;
    string cmd;
    while (true)
    {
        cin >> cmd;
        if (cmd == "quit")
        {
            cout << "MidServer Bye~" << endl;
            return;
        }
    }
}

int MidServer::task_listen(MidServer *self)
{
    int listen_sock = self->Server::get_sock();
    int client_sock = self->Client::get_sock();
    int AC_socket;                  // 客户端套接字
    struct sockaddr_in client_addr; // 客户端地址
    socklen_t len_client_addr;      // 客户端地址长度
    len_client_addr = sizeof(client_addr);

    while (true)
    {
        AC_socket = accept(listen_sock, (struct sockaddr *)&client_addr, &len_client_addr);
        if (AC_socket == -1)
        {
            perror("Error");
            return -1;
        }

        //获取系统时间
        time_t now_t;
        time(&now_t);

        //打印接收到的客户端地址信息
        cout << "\r" << ctime(&now_t) << "IP: " << inet_ntoa(client_addr.sin_addr)
             << " Port: " << htons(client_addr.sin_port) << endl;

        struct sockaddr_in server_addr = self->Client::get_server_addr();

        // 另一端（中间人客户端）连接服务器
        int ret = connect(client_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (ret == -1)
        {
            perror("Error");
            return -1;
        }

        // start a thread dealing with the client A --> C --> B
        self->set_thread_backward(new thread(Client::client_recv, self));
        self->set_thread_forward(new thread(Server::server_recv, self));

        thread *thread_forward = self->get_thread_forward();
        thread *thread_backward = self->get_thread_backward();

        // forward thread is connect with the Client(A <-----> C)
        self->bind_thread_sock(thread_forward->get_id(), AC_socket);

        self->bind_threads(thread_forward->get_id(), thread_backward->get_id());

        thread_backward->detach();
        thread_forward->detach();
    }
    return 0;
}

// task forward thread
int MidServer::deal_appdata_server(char *buf, u_short len_payload, Security_param &sp)
{
    int sock = Server::get_sock_by_thread_id(std::this_thread::get_id());

    struct sockaddr_in client_addr;
    socklen_t len_client_addr = sizeof(client_addr);

    // get client addr by socket
    getpeername(sock, (struct sockaddr *)&client_addr, &len_client_addr);

    cerr << "========================================" << endl;

    // got data from the client A --> C
    // decrypt data using KeyAC, this time, we played a server role
    appData_hdr *app_hdr = (appData_hdr *)buf;
    string plain = data_dec((byte *)buf, len_payload, &sp, false);

    cout << "[" << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << "]: ";

    // deal with data from the client
    // =============================================================================

    cout << plain << endl;

    Security_param *spC_B = thread_spC_B[std::this_thread::get_id()];

    // forward to the server C --> B
    // encrypt data using KeyCB, this time, we play a client role
    string cipher = data_enc((byte *)plain.data(), plain.size(), spC_B, app_hdr->seq_no, false);

    // dynamically allocate space for data
    appData_hdr *app_hdr_server = (appData_hdr *)malloc(sizeof(appData_hdr) + cipher.size());
    app_hdr_server->seq_no = app_hdr->seq_no;
    std::memcpy(app_hdr_server->data, cipher.data(), cipher.size());

    // get sock between C -- B
    int sock_client = thread_sockC_B[std::this_thread::get_id()];
    Sender sender_client(sock_client);

    // send to the server
    ssize_t ret = sender_client.send((char *)app_hdr_server, sizeof(appData_hdr) + cipher.size(), APPLICATION_DATA);

    // recycle the memory
    std::free(app_hdr_server);
    app_hdr_server = nullptr;

    // =============================================================================
    if (plain.substr(0, 4) == "quit")
    {
        cerr << "\rClient quit" << endl;
        shutdown(sock, SHUT_WR);
        close(sock);
        return -2;
    }
    deal_error(sock, ret);
    return 0;
}

// task backward thread
int MidServer::deal_appdata_client(char *buf, u_short len_payload, Security_param &sp)
{
    // decrypt data using KeyBC, this time, we played a client role
    string plain = data_dec((byte *)buf, len_payload, &sp, true);
    appData_hdr *app_hdr = (appData_hdr *)buf;
    cout << "client recv: " << plain << endl;

    // forward to the client C --> A
    Security_param *spA_C = thread_spA_C[std::this_thread::get_id()];

    // encrypt data using KeyAC, this time, we played a server role
    string cipher = data_enc((byte *)plain.data(), plain.size(), spA_C, app_hdr->seq_no, true);

    // get sock between A -- C
    Sender sender(thread_sockA_C[std::this_thread::get_id()]);
    appData_hdr *app_hdr_server = (appData_hdr *)malloc(sizeof(appData_hdr) + cipher.size());
    app_hdr_server->seq_no = app_hdr->seq_no;
    std::memcpy(app_hdr_server->data, cipher.data(), cipher.size());

    ssize_t ret = sender.send((char *)app_hdr_server, sizeof(appData_hdr) + cipher.size(), APPLICATION_DATA);

    std::free(app_hdr_server);
    app_hdr_server = nullptr;

    int sock_client = thread_sockC_B[std::this_thread::get_id()];
    if (plain.substr(0, 4) == "quit")
    {
        cerr << "receive thread exit" << endl;
        shutdown(sock_client, SHUT_WR);
        close(sock_client);
        return -2;
    }

    deal_error(sock_client, ret);
    return 0;
}

void MidServer::bind_threads(thread::id f, thread::id b)
{
    thread_fb[f] = b;
    thread_bf[b] = f;
}

void MidServer::set_threads_sp(Security_param *sp, bool is_AC, bool is_forward)
{
    auto &thread_sp = is_AC ? thread_spA_C : thread_spC_B;
    auto &thread_map = is_forward ? thread_fb : thread_bf;

    thread_sp[std::this_thread::get_id()] = sp;
    thread_sp[thread_map[std::this_thread::get_id()]] = sp;
}

void MidServer::set_threads_sock(int sock, bool is_AC, bool is_forward)
{
    auto &thread_sock = is_AC ? thread_sockA_C : thread_sockC_B;
    auto &thread_map = is_forward ? thread_fb : thread_bf;

    thread_sock[std::this_thread::get_id()] = sock;
    thread_sock[thread_map[std::this_thread::get_id()]] = sock;
}

void MidServer::set_thread_forward(thread *t)
{
    this->thread_forward = t;
}

void MidServer::set_thread_backward(thread *t)
{
    this->thread_backward = t;
}

thread *MidServer::get_thread_forward()
{
    return this->thread_forward;
}

thread *MidServer::get_thread_backward()
{
    return this->thread_backward;
}

void MidServer::init_psk(const char *pskfile)
{
    Client::init_psk(pskfile);
    Server::init_psk(pskfile);
}
