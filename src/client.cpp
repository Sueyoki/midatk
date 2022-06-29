
#include "../include/client.h"

Client::Client() : Client("127.0.0.1", 20411)
{
    fprintf(stdout, "not specify the server Ip and port, using default %s:%i\n", serverIp, port);
}

Client::Client(const char *serverIp) : Client(serverIp, 20411)
{
    fprintf(stdout, "not specify the server port, using default %s:%i\n", serverIp, port);
}

Client::Client(int port) : Client("127.0.0.1", port)
{
    fprintf(stdout, "not specify the server Ip, using default Ip %s:%i\n", "127.0.0.1", port);
}

Client::Client(const char *serverIp, int port) : serverIp(serverIp), pskfile(nullptr), port(port)
{
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1)
    {
        perror("Error");
        return;
    }
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(serverIp);
    server_addr.sin_port = htons(port);
    sp = new Security_param;
}

Client::~Client()
{
    // 原子对象，用于指示线程结束
    done = true;

    // 将套接字设置为非阻塞，等待线程退出
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    // 等待线程关闭
    if (fut_recv.valid())
    {
        std::cout << "Waiting for recv thread to finish" << std::endl;
        std::future_status status = fut_recv.wait_for(std::chrono::milliseconds(0));
        while(true)
        {
            if (status == std::future_status::deferred)
            {
                std::cout << "deferred\n";
            }
            else if (status == std::future_status::timeout)
            {
                std::cout << "timeout\n";
            }
            else if (status == std::future_status::ready)
            {
                std::cout << "ready!\n";
                break;
            }
            status = fut_recv.wait_for(std::chrono::milliseconds(250));
        }
    }

    if (fut_send.valid())
    {
        std::cout << "Waiting for send thread to finish" << std::endl;
        std::future_status status = fut_send.wait_for(std::chrono::milliseconds(0));
        while(true)
        {
            if (status == std::future_status::deferred)
            {
                std::cout << "deferred\n";
            }
            else if (status == std::future_status::timeout)
            {
                std::cout << "timeout\n";
            }
            else if (status == std::future_status::ready)
            {
                std::cout << "ready!\n";
                break;
            }
            status = fut_send.wait_for(std::chrono::milliseconds(250));
        } 
    }

    delete sp;

    shutdown(sock, SHUT_WR);
    close(sock);
    cout << "Client Bye~" << endl;
}

void Client::start()
{
    cout << "Client start" << endl;
    ret = connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret == -1)
    {
        perror("Error");
        return;
    }
    fut_recv = std::async(std::launch::async, client_recv, this);
    fut_send = std::async(std::launch::async, client_send, this);
    fut_send.wait();
}

int Client::client_recv(Client *self)
{
    cout << "recv thread started" << endl;
    int sock = self->sock;
    Security_param &sp = *self->sp;

    Receiver reader(sock);
    Sender sender(sock);
    char buf[LEN_BUF];
    u_short len_payload;
    u_char msg_type;
    ssize_t ret;

    // DIFFIE_HELLMAN
    Integer P, g;

#ifdef USE_DEFAULT_GPQ
    dh_pqg_generate(self->dh);
#endif

    while (!self->done)
    {
        ret = reader.recv(buf, len_payload, msg_type);

        if (ret == 0)
        {
            cout << "Server closed socket" << endl;
            return 0;
        }

        // 切换非阻塞模式使线程终止
        if (ret < 0)
        {
            if (errno == EWOULDBLOCK)
                break;
        }

        deal_error(sock, ret);

        switch (msg_type)
        {
        case HANDSHAKE:
        {
            struct HandShake_hdr *hs_hdr;
            hs_hdr = (HandShake_hdr *)buf;
            switch (hs_hdr->type)
            {
            case SERVER_HELLO:
            {
                // 保存server random到Security param中
                memcpy(sp.server_random, hs_hdr->rand, LEN_RANDOM_BYTES);
                
                cerr << "server hello: " << endl;
                cerr << "server random: " << endl;
                print_hex(sp.server_random, LEN_RANDOM_BYTES);

                // 发送CLIENT HELLO
                HandShake_hdr *hs_hdr = new HandShake_hdr;

                // 产生client random
                AutoSeededRandomPool *rnd = new AutoSeededRandomPool;
                rnd->GenerateBlock(hs_hdr->rand, LEN_RANDOM_BYTES);

                // 保存client random到Security param中
                memcpy(sp.client_random, hs_hdr->rand, LEN_RANDOM_BYTES);

                // 发送client random给服务器
                hs_hdr->type = CLIENT_HELLO;
                hs_hdr->len = LEN_RANDOM_BYTES;
                ret = sender.send((char *)hs_hdr, sizeof(HandShake_hdr), HANDSHAKE);

                delete hs_hdr;
                hs_hdr = nullptr;
                delete rnd;
                rnd = nullptr;

                deal_error(sock, ret);
            }
            break;

            default:
                break;
            }
        }
        break;

#ifndef USE_DEFAULT_GPQ
        case DIFFIE_HELLMAN:
        {
            struct DH_hdr *dh_hdr;
            dh_hdr = (struct DH_hdr *)buf;

            P.Decode(dh_hdr->P, sizeof(dh_hdr->P));
            g.Decode(dh_hdr->g, sizeof(dh_hdr->g));

            self->dh.AccessGroupParameters().Initialize(P, g);
            break;
        }
#endif

        case SERVER_KEY_EXCHANGE:
        {
            struct Key_change_hdr *kc_hdrA;
            kc_hdrA = (struct Key_change_hdr *)buf;

            cerr << "kc_hdrA->pubkey: " << endl;
            print_hex((byte *)&kc_hdrA->pubkey, LEN_PUBLIC_KEY);

            // 利用服务器的模素数P和生成元g，产生客户端公私钥
            cerr << "利用服务器的模素数P和生成元g，产生客户端公私钥..." << endl;
            SecByteBlock privB_sec, pubB;
            dh_key_generate(self->dh, privB_sec, pubB);

            // 发送客户端公钥给服务器
            cerr << "发送客户端公钥给服务器..." << endl;

            Key_change_hdr kc_hdrB;

            memcpy(kc_hdrB.pubkey, pubB.BytePtr(), pubB.SizeInBytes());
            cerr << "kc_hdrB.pubkey: " << endl;
            print_hex(kc_hdrB.pubkey, LEN_PUBLIC_KEY);

            ret = sender.send((char *)&kc_hdrB, sizeof(kc_hdrB), CLIENT_KEY_EXCHANGE);
            deal_error(sock, ret);
            // ====================================================================

            // 产生最后协商后的密钥
            cerr << "产生最后协商后的密钥..." << endl;
            cerr << "privB_sec: " << endl;
            print_hex(privB_sec.BytePtr(), privB_sec.SizeInBytes());

            Integer shared_secret;
            dh_key_generate(self->dh, privB_sec, kc_hdrA->pubkey, LEN_PUBLIC_KEY, shared_secret);

            cerr << "Shared secret (B): " << std::hex << shared_secret << endl;

            const char *psk_file = self->getpsk();
            if (psk_file)
            {
                std::ifstream fin(psk_file);
                string psk;
                fin >> psk;

                u_short len;
                u_char *pos;
                
                // 限制pre-master secret为48字节，方便储存
                // +-------------------+-----------------+----------+----------+
                // |shared secret len  |  shared secret  |  psk len |    psk   |
                // +-------------------+-----------------+----------+----------+
                // |      2Bytes       |      28Bytes    |   2Bytes |  16Bytes |
                // +-------------------+-----------------+----------+----------+

                // 48 - 2 - 2 - 16
                len = 28;
                pos = (u_char *)mempcpy(sp.pre_master_secert, (char *)&len, sizeof(u_short));
                shared_secret.Encode(pos, 28);

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
                pos = (u_char *)mempcpy(pos + 28, (char *)&len, sizeof(u_short));

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
            gen_master_secret(*self->sp);

            cerr << "master secret: " << endl;
            print_hex(sp.master_secret, LEN_MASTER_SECERT);

            gen_GCM_param(*self->sp);

            cerr << "client write iv:" << endl;
            print_hex(sp.client_write_iv, sizeof(sp.client_write_iv));
            cerr << "server write iv:" << endl;
            print_hex(sp.server_write_iv, sizeof(sp.server_write_iv));
            cerr << "client write key:" << endl;
            print_hex(sp.client_write_key, sizeof(sp.client_write_key));
            cerr << "server write key:" << endl;
            print_hex(sp.server_write_key, sizeof(sp.server_write_key));

            // the sp is between B and C
            // dealing with data from server and send to the client, so backward
            self->set_threads_sp(&sp, false, false);
            self->set_threads_sock(sock, false, false);
        }
        break;

        case CHANGE_CIPHER_SPEC:
            cerr << "Server change cipher spec ok" << endl;
            break;

        case APPLICATION_DATA:
        {
            ret = self->deal_appdata_client(buf, len_payload, *self->sp);

            // peer closed
            if (ret < 0)
            {
                if (ret == -2)
                    return 0;
                else
                    return ret;
            }
        }

        default:
            break;
        }
    }
    return 0;
}

int Client::client_send(Client *self)
{
    cout << "Send thread started" << endl;
    int sock = self->sock;
    size_t seq_no = 0;
    string data;
    ssize_t ret;
    Sender sender(sock);
    Receiver reader(sock);
    while (true)
    {
        std::getline(cin, data);

        string cipher = data_enc((byte *)data.data(), data.size(), self->sp, seq_no, false);

        appData_hdr *app_hdr = (appData_hdr *)malloc(sizeof(appData_hdr) + cipher.size());
        app_hdr->seq_no = seq_no++;
        memcpy(app_hdr->data, cipher.data(), cipher.size());
        ret = sender.send((char *)app_hdr, sizeof(appData_hdr) + cipher.size(), APPLICATION_DATA);

        free(app_hdr);
        app_hdr = nullptr;

        deal_error(sock, ret);
        cout << "[Send OK]" << endl;
        if (data == "quit")
        {
            cerr << "Send thread exit" << endl;
            self->done = true;
            break;
        }
    }
    return 0;
}

Security_param *Client::get_sp()
{
    return this->sp;
}

int Client::get_sock()
{
    return this->sock;
}

struct sockaddr_in Client::get_server_addr()
{
    return this->server_addr;
}

int Client::deal_appdata_client(char *buf, u_short len_payload, Security_param &sp)
{
    string plain = data_dec((byte *)buf, len_payload, &sp, true);

    cout << "client recv: " << plain << endl;
    if (plain == "quit")
    {
        cerr << "receive thread exit" << endl;
        shutdown(sock, SHUT_WR);
        close(sock);
        return 0;
    }
    return 0;
}

// declared for override
void Client::set_threads_sp(Security_param *sp, bool is_AC, bool is_forward){}

void Client::set_threads_sock(int sock, bool is_AC, bool is_forward){}

void Client::init_psk(const char *pskfile)
{
    this->pskfile = pskfile;
}

const char *Client::getpsk()
{
    return this->pskfile;
}