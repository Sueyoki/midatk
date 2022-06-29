
#include "../include/client.h"
const char *err_out_file = "/root/course/gitcode/midatk/log/client_log.txt";
int main(int argc, char *argv[])
{
    char opt;
    bool err_file_flag = false;
    string serverIp;
    string err_file, pskfile;
    u_short port = 0;
    Client *client;
    FILE *fp;

    while ((opt = getopt(argc, argv, "i:p:f::k:h")) != EOF)
    {
        switch (opt)
        {
        case 'i':
            serverIp = string(optarg);
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'f':
            err_file_flag = true;
            if (optarg)
                err_file = string(optarg);
            break;
        case 'k':
            pskfile = string(optarg);
            break;

        case 'h':
        case '?':
        default:
            cout << "Usage: " << argv[0] << " [-i <IP>] [-p <port>]"
                 << " [-f [<path>]] [-k <path>] -h" << endl;
            if (opt == 'h')
            {
                cout << endl
                     << "Commands:" << endl;
                cout << "Specify the server address." << endl;
                cout << "\t-i server ip    \tSpecify the server IP" << endl;
                cout << "\t-p server port  \tSpecify the server Port" << endl;

                cout << endl
                     << "Error log output." << endl;
                cout << "\t-f [output path]\tOutput the log(if no path, use standard output)" << endl;

                cout << endl
                     << "Use pre-shared-key." << endl;
                cout << "\t-k psk file path\tUse psk to protect the connection(prevent MITM)" << endl;

                cout << endl
                     << "Help." << endl;
                cout << "\t-h              \tPrint helps" << endl;
            }
            return 1;
        }
    }

    if (err_file_flag)
    {
        if (err_file.empty())
            cout << "Using default output file path: " << err_out_file << endl;
        else
            err_out_file = err_file.data();
    }
    else
        err_out_file = "/dev/null";

    fp = fopen(err_out_file, "w");
    if (!fp)
    {
        cout << "File open failed, using standard output" << endl;
        perror("Error");
    }
    else
    {
        fclose(fp);
        fp = freopen(err_out_file, "w", stderr);
    }

    if (serverIp.empty())
        client = port ? new Client(port) : new Client();
    else
        client = port ? new Client(serverIp.data(), port) : new Client(serverIp.data());

    if (!pskfile.empty())
    {
        client->init_psk(pskfile.data());
        cout << "Using PSK file: " << pskfile << endl;
    }

    client->start();

    if (fp)
        fclose(fp);

    delete client;

    return 0;
}