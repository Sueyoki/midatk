
#include "../include/server.h"
Server::Server() : Server(20410)
{
    fprintf(stdout, "not specify the server port, using default %s:%i\n", "127.0.0.1", port);
}

Server::Server(int port) : port(port), pskfile(nullptr)
{
    // 创建服务器端套接字
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1)
    {
        perror("Error");
        return;
    }

    // 初始化服务器地址
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // 允许套接字和一个已在使用中的地址捆绑
    int opt_val = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));

    // 将服务器地址与套接字绑定
    bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
}

void Server::start()
{
    int ret = listen(sock, MAX_CONN_NUM);

    if (ret == -1)
    {
        cerr << "listen failed" << endl;
        return;
    }

    thread thread_listen(task_listen, this);

    thread_listen.detach();

    cout << "Server started listening at " << inet_ntoa(server_addr.sin_addr) << ":" << ntohs(server_addr.sin_port) << endl;
    string cmd;
    while (true)
    {
        cin >> cmd;
        if (cmd == "quit")
        {
            return;
        }
    }
}

void Server::init_psk(const char *pskfile)
{
    this->pskfile = pskfile;
}

const char *Server::getpsk()
{
    return this->pskfile;
}

int Server::task_listen(Server *self)
{
    cout << "listen thread started" << endl;
    int sock = self->sock;
    int client_socket;              // 客户端套接字
    struct sockaddr_in client_addr; // 客户端地址
    socklen_t len_client_addr;      // 客户端地址长度
    len_client_addr = sizeof(client_addr);

    while (true)
    {
        client_socket = accept(sock, (struct sockaddr *)&client_addr, &len_client_addr);
        // cout << "Client socket: " << client_socket << endl;
        if (client_socket == -1)
        {
            perror("Error");
            return -1;
        }

        //获取系统时间
        time_t now_t;
        time(&now_t);

        //打印接收到的客户端地址信息
        cout << "\r" << ctime(&now_t) << "IP: " << inet_ntoa(client_addr.sin_addr) << " Port: " << htons(client_addr.sin_port) << endl;

        // 建立线程处理与客户端间通信
        std::unique_ptr<thread> thread_worker = (std::unique_ptr<thread>)new thread(server_recv, self);
        self->threads_sock[thread_worker->get_id()] = client_socket;
        thread_worker->detach();
    }
}

int Server::deal_appdata_server(char *buf, u_short len_payload, Security_param &sp)
{
    int sock = threads_sock[std::this_thread::get_id()];
    Sender sender(sock);
    struct sockaddr_in client_addr;
    socklen_t len_client_addr = sizeof(client_addr);
    getpeername(sock, (struct sockaddr *)&client_addr, &len_client_addr);
    size_t seq_no = 0;
    cerr << "========================================" << endl;
    string plain = data_dec((byte *)buf, len_payload, &sp, false);

    cout << "[" << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << "]: ";
    cout << plain << endl;

    plain += "+ACK";

    string cipher = data_enc((byte *)plain.data(), plain.size(), &sp, seq_no, true);

    appData_hdr *app_hdr_server = (appData_hdr *)malloc(sizeof(appData_hdr) + cipher.size());
    app_hdr_server->seq_no = seq_no++;
    memcpy(app_hdr_server->data, cipher.data(), cipher.size());

    ssize_t ret = sender.send((char *)app_hdr_server, sizeof(appData_hdr) + cipher.size(), APPLICATION_DATA);

    free(app_hdr_server);
    app_hdr_server = nullptr;

    if (plain == "quit")
    {
        cerr << "\rClient quit" << endl;
        shutdown(sock, SHUT_WR);
        close(sock);
        return -2;
    }
    deal_error(sock, ret);
    return 0;
}

Server::~Server()
{
    shutdown(sock, SHUT_WR);
    close(sock);
    for (auto &ts : threads_sock)
    {
        int s = ts.second;
        shutdown(s, SHUT_WR);
        close(s);
    }
    cout << "Server Bye~" << endl;
}

int Server::server_recv(Server *self)
{
    int sock = self->threads_sock[std::this_thread::get_id()];
    ssize_t ret;
    char buf[LEN_RECV_BUF];
    struct sockaddr_in client_addr;
    socklen_t len_client_addr = sizeof(client_addr);
    Sender sender(sock);
    Receiver reader(sock);
    Security_param sp;
    bool authorized = false;

    getpeername(sock, (struct sockaddr *)&client_addr, &len_client_addr);

    dh_pqg_generate(self->dh);

    Integer P, g;
    SecByteBlock privA_sec, pubA_sec;
    P = self->dh.AccessGroupParameters().GetModulus();
    g = self->dh.AccessGroupParameters().GetGenerator();
    dh_key_generate(self->dh, privA_sec, pubA_sec);

    print_integer(P, "P");
    print_integer(g, "g");

    // 发送SERVER HELLO
    cerr << "[" << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << "]" << endl;
    cerr << "发送SERVER HELLO..." << endl;

    HandShake_hdr *hs_hdr_server = new HandShake_hdr;
    hs_hdr_server->len = LEN_RANDOM_BYTES;
    hs_hdr_server->type = SERVER_HELLO;

    // 产生server random
    AutoSeededRandomPool *rnd = new AutoSeededRandomPool;
    rnd->GenerateBlock(hs_hdr_server->rand, LEN_RANDOM_BYTES);
    memcpy(sp.server_random, hs_hdr_server->rand, LEN_RANDOM_BYTES);
    delete rnd;
    rnd = nullptr;

    // 发送server random 给客户端
    ret = sender.send((char *)hs_hdr_server, sizeof(HandShake_hdr), HANDSHAKE);
    deal_error(sock, ret);

    delete hs_hdr_server;
    hs_hdr_server = nullptr;

    while (true)
    {
        cerr << "receiving..." << endl;
        u_short len_payload;
        u_char msg_type;
        ret = reader.recv(buf, len_payload, msg_type);

        if (ret == 0)
        {
            cerr << "[" << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << "]" << endl;
            cerr << "Client closed socket" << endl;
            return 0;
        }

        // 切换非阻塞模式使线程终止
        if (ret < 0)
        {
            if (errno == EWOULDBLOCK)
            {
                break;
            }
        }

        deal_error(sock, ret);

        switch (msg_type)
        {
        case HANDSHAKE:
        {
            struct HandShake_hdr *hs_hdr;
            hs_hdr = (struct HandShake_hdr *)buf;
            switch (hs_hdr->type)
            {
            case CLIENT_HELLO:
            {
                memcpy(sp.client_random, hs_hdr->rand, sizeof(hs_hdr->rand));
                cerr << "client hello: " << endl;
                cerr << "client random: " << endl;
                print_hex(sp.client_random, sizeof(sp.client_random));

#ifndef USE_DEFAULT_GPQ
                // 发送Diffie-Hellman模数和生成元g(α)
                cerr << "[" << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << "]" << endl;
                cerr << "发送Diffie-Hellman模数和生成元g(α)..." << endl;

                struct DH_hdr *dh_hdrA = new DH_hdr;
                P.Encode(dh_hdrA->P, sizeof(dh_hdrA->P));
                g.Encode(dh_hdrA->g, sizeof(dh_hdrA->g));
                ret = sender.send((char *)dh_hdrA, sizeof(DH_hdr), DIFFIE_HELLMAN);
                deal_error(sock, ret);

                delete dh_hdrA;
                dh_hdrA = nullptr;
#endif

                // 发送Server pubkey
                cerr << "[" << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << "]" << endl;
                cerr << "发送Server pubkey..." << endl;

                cerr << "pubA:" << endl;
                print_hex(pubA_sec.BytePtr(), pubA_sec.SizeInBytes());

                struct Key_change_hdr *kc_hdrA = new Key_change_hdr;
                memcpy(kc_hdrA->pubkey, pubA_sec.BytePtr(), pubA_sec.SizeInBytes());

                ret = sender.send((char *)kc_hdrA, sizeof(Key_change_hdr), SERVER_KEY_EXCHANGE);
                deal_error(sock, ret);

                delete kc_hdrA;
                kc_hdrA = nullptr;
            }

            break;

            default:
                break;
            }
        }
        break;

        case CLIENT_KEY_EXCHANGE:
        {
            Key_change_hdr *kc_hdrB;
            kc_hdrB = (Key_change_hdr *)buf;

            Integer shared_secret;

            // 产生协商后密钥
            dh_key_generate(self->dh, privA_sec, kc_hdrB->pubkey, sizeof(kc_hdrB->pubkey), shared_secret);

            cerr << "Shared secret (A): " << std::hex << shared_secret << endl;

            const char *psk_file = self->getpsk();
            if (psk_file)
            {
                std::ifstream fin(psk_file);
                string psk;
                fin >> psk;

                u_short len;

                len = 28;
                memcpy(sp.pre_master_secert, (char *)&len, sizeof(u_short));
                shared_secret.Encode(sp.pre_master_secert + sizeof(u_short), 28);

                HexEncoder encoder(new FileSink(std::cout));
                CryptoPP::Weak::MD5 hash;
                string digest;

                hash.Update((const byte *)psk.data(), psk.size());
                digest.resize(hash.DigestSize());
                hash.Final((byte *)digest.data());

                // std::cout << "Digest: ";
                // StringSource(digest, true, new Redirector(encoder));
                // std::cout << std::endl;

                len = hash.DigestSize();
                u_char *pos = (u_char *)mempcpy(sp.pre_master_secert + sizeof(u_short) + 28, (char *)&len, sizeof(u_short));

                memcpy(pos, digest.data(), digest.size());
            }

            else
            {
                // 保存(Pre-)master secret
                shared_secret.Encode(sp.pre_master_secert, LEN_PRE_MASTER_SECRET);
            }

            cerr << "pre master secret: " << endl;
            print_hex(sp.pre_master_secert, LEN_PRE_MASTER_SECRET);

            ret = sender.send(buf, 1, CHANGE_CIPHER_SPEC);
            deal_error(sock, ret);

            // 扩展计算master secret
            gen_master_secret(sp);

            cerr << "master secret: " << endl;
            print_hex(sp.master_secret, LEN_MASTER_SECERT);

            gen_GCM_param(sp);

            cerr << "client write iv:" << endl;
            print_hex(sp.client_write_iv, sizeof(sp.client_write_iv));
            cerr << "server write iv:" << endl;
            print_hex(sp.server_write_iv, sizeof(sp.server_write_iv));
            cerr << "client write key:" << endl;
            print_hex(sp.client_write_key, sizeof(sp.client_write_key));
            cerr << "server write key:" << endl;
            print_hex(sp.server_write_key, sizeof(sp.server_write_key));

            authorized = true;

            self->set_threads_sp(&sp, true, true);
            self->set_threads_sock(sock, true, true);
        }
        break;

        case APPLICATION_DATA:
        {
            if (!authorized)
            {
                cerr << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port);
                cerr << " is not authorized" << endl;
                break;
            }
            ret = self->deal_appdata_server(buf, len_payload, sp);
            // Client closed
            if (ret < 0)
            {
                // smart pointer delete
                self->threads_sock.erase(std::this_thread::get_id());
                if (ret == -2)
                    return 0;
                else
                    return ret;
            }
        }
        break;

        case CHANGE_CIPHER_SPEC:
            cerr << "client change cipher spec ok" << endl;
            break;
        default:
            break;
        }
    }
    return 0;
}

void Server::set_threads_sp(Security_param *sp, bool is_AC, bool is_forward) {}

void Server::set_threads_sock(int sock, bool is_AC, bool is_forward) {}

int Server::get_sock()
{
    return this->sock;
}

struct sockaddr_in Server::get_listen_addr()
{
    return this->server_addr;
}

void Server::bind_thread_sock(thread::id id, int sock)
{
    this->threads_sock[id] = sock;
}

int Server::get_sock_by_thread_id(thread::id id)
{
    return this->threads_sock[id];
}