/*
 * iptvscanner.cpp - IPTV 组播扫描（Cortex-A9 / HS8145X6 适配）
 * 修复：全局作用域误调函数导致的编译错误
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <iostream>

using namespace std;

char nicname[1024] = {0};

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
        close(s);
        return -1;
    }

    pcap_t *device = pcap_open_live(nicname, 65535, 1, 1, errBuf);
    if (!device)
    {
        cout << "error: pcap_open_live():" << errBuf << endl;
        close(s);
        return -1;
    }

    /* 需要时放在这里，不能写在函数外面
    pcap_setnonblock(device, 1, errBuf);
    pcap_set_immediate_mode(device, 1);
    */

    char strfilter[64] = "udp and host ";
    char *strip = strfilter + strlen("udp and host ");
    inet_ntop(AF_INET, &ip, strip, 16);

    struct bpf_program filter;
    if (pcap_compile(device, &filter, strfilter, 1, 0) == 0)
    {
        pcap_setfilter(device, &filter);
        pcap_freecode(&filter);
    }

    usleep(150000);

    struct pcap_pkthdr packet;
    const u_char *pktStr = pcap_next(device, &packet);
    if (pktStr)
    {
        struct udphdr *udphdr = (struct udphdr *)(pktStr + 14 + 20);
        printf("#EXTINF:-1,%s:%d\nrtp://%s:%d\n",
               strip, ntohs(udphdr->dest), strip, ntohs(udphdr->dest));
    }
    pcap_close(device);

    err = setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, (const char *)&mreq, sizeof(mreq));
    close(s);
    return err < 0 ? -1 : 0;
}

int main(int argc, char *argv[])
{
    pcap_if_t *alldevs;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    int inum;

    if (argc != 3)
    {
        cout << "usage:" << endl
             << "\t" << argv[0] << " \"start of ip\" \"end of ip\" " << endl;
        cout << "\t eg.. " << argv[0] << " 239.3.1.1 239.3.1.254" << endl;
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
    return 0;
}
