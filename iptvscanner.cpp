/*
 * iptvscanner.cpp - IPTV 组播扫描
 * 适配：Linux（ARMv7 / MIPS / x86_64）+ Windows（x86_64，需安装 Npcap）
 */
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <iostream>

using namespace std;

#ifdef _WIN32
#define CLOSE_SOCK closesocket
#define SLEEP_US(x) Sleep((x) / 1000) /* Windows 的 Sleep 单位是毫秒 */
#else
#define CLOSE_SOCK close
#define SLEEP_US(x) usleep(x)
#endif

char nicname[1024] = {0};

/* 取 UDP 目的端口（网络字节序）。各平台 udphdr 定义不同，这里统一处理 */
static unsigned short udp_dport_of(const u_char *pkt)
{
#if defined(_WIN32)
    struct my_udphdr
    {
        unsigned short sport;
        unsigned short dport;
        unsigned short len;
        unsigned short sum;
    };
    const my_udphdr *u = (const my_udphdr *)(pkt + 14 + 20);
    return u->dport;
#else
    const struct udphdr *u = (const struct udphdr *)(pkt + 14 + 20);
#if defined(__APPLE__)
    return u->uh_dport;
#else
    return u->dest;
#endif
#endif
}

int iptvscan(unsigned int ip)
{
    char errBuf[PCAP_ERRBUF_SIZE] = {0};
    int s;
    int err = -1;
    ip = htonl(ip);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1)
    {
        return -1;
    }

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = ip;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    err = setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *)&mreq, sizeof(mreq));
    if (err < 0)
    {
        CLOSE_SOCK(s);
        return -1;
    }

    pcap_t *device = pcap_open_live(nicname, 65535, 1, 1, errBuf);
    if (!device)
    {
        cout << "error: pcap_open_live():" << errBuf << endl;
        CLOSE_SOCK(s);
        return -1;
    }

    char strfilter[64] = "udp and host ";
    char *strip = strfilter + strlen("udp and host ");
    inet_ntop(AF_INET, &ip, strip, 16);

    struct bpf_program filter;
if (pcap_compile(device, &filter, strfilter, 1, 0) == 0)
    {
        pcap_setfilter(device, &filter);
        pcap_freecode(&filter);
    }

    SLEEP_US(150000);

    struct pcap_pkthdr packet;
    const u_char *pktStr = pcap_next(device, &packet);
    if (pktStr)
    {
        unsigned short dport = ntohs(udp_dport_of(pktStr));
        printf("#EXTINF:-1,%s:%d\nrtp://%s:%d\n", strip, dport, strip, dport);
    }
    pcap_close(device);

    setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, (const char *)&mreq, sizeof(mreq));
    CLOSE_SOCK(s);
    return 0;
}

int main(int argc, char *argv[])
{
    pcap_if_t *alldevs;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    int inum = 0;

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("WSAStartup failed\n");
        return -1;
    }
#endif

    if (argc != 3)
    {
        cout << "usage:" << endl
             << "\t" << argv[0] << " \"start of ip\" \"end of ip\" " << endl;
        cout << "\t eg.. " << argv[0] << " 239.3.1.1 239.3.1.254" << endl;
#ifdef _WIN32
        WSACleanup();
#endif
        return -1;
    }

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    pcap_if_t *d;
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found!\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    fflush(stdout);
    if (cin >> inum)
    {
        /* ok */
    }

    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    cout << "#EXTM3U name=\"bj-unicom-iptv\"" << endl;

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
        ;

    snprintf(nicname, sizeof(nicname), "%s", d->name);
    pcap_freealldevs(alldevs);

    unsigned int ipstart = 0, ipend = 0;
    inet_pton(AF_INET, argv[1], &ipstart);
    inet_pton(AF_INET, argv[2], &ipend);
    ipstart = ntohl(ipstart);
    ipend = ntohl(ipend);

    for (unsigned int ip = ipstart; ip <= ipend; ip++)
    {
        iptvscan(ip);
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
