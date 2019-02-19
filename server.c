#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include "tcp_utils.h"
#include "tun_utils.h"

#ifndef PRINT_HEX
#define PRINT_HEX(buf, len)                                                                         \
    do{                                                                                             \
        if(buf != NULL && len > 0)                                                                  \
        {                                                                                           \
            int loop = 0;                                                                           \
            for(loop = 0; loop < len; loop++)                                                       \
                printf("0x%02hhx%s", (unsigned char)buf[loop], (loop+1) % 16 != 0 ? ", " : ",\n");  \
            if(loop % 16 != 0) printf("\n");                                                        \
        }                                                                                           \
    }while(0);
#endif

#define SERVER_IP "0.0.0.0"
#define SERVER_PORT 443

#define TUN_NAME "tun0"
#define TUN_IP "10.10.1.1"
#define TUN_MASK "255.255.0.0"

#define PEER_SUBNET "192.168.10.0"
#define PEER_NETMASK "255.255.255.0"

#define MAX_BUFFER_SIZE 65536

int main(int argc, char *argv[])
{
    int rv = 0;
    int fd = 0;
    int net_fd = 0;
    int tun_fd[MAX_QUEUE_NUM] = {0};
    int tun_length = MAX_BUFFER_SIZE;
    int net_length = MAX_BUFFER_SIZE;
    unsigned char tun_buffer[MAX_BUFFER_SIZE] = {0};
    unsigned char net_buffer[MAX_BUFFER_SIZE] = {0};

    rv = tun_open(TUN_NAME, TUN_IP, TUN_MASK, tun_fd, MAX_QUEUE_NUM);
    if(rv < 0)
    {
        fprintf(stderr, "%s %s:%u - %d:%s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        goto ErrP;
    }
    rv = tun_add_route(PEER_SUBNET, PEER_NETMASK, TUN_IP, TUN_NAME);
    if(rv < 0)
    {
        fprintf(stderr, "%s %s:%u - %d:%s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        goto ErrP;
    }

    fd = tcp_socket();
    if(fd < 0)
    {
        fprintf(stderr, "%s %s:%u - %d:%s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        goto ErrP;
    }
    rv = tcp_bind(fd, SERVER_IP, SERVER_PORT);
    if(rv < 0)
    {
        fprintf(stderr, "%s %s:%u - %d:%s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        goto ErrP;
    }
    rv = tcp_listen(fd, 256);
    if(rv < 0)
    {
        fprintf(stderr, "%s %s:%u - %d:%s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        goto ErrP;
    }
    fprintf(stdout, "%s %s:%u - tcp server %s:%hu\n", __FUNCTION__, __FILE__, __LINE__, SERVER_IP, SERVER_PORT);

    int i = 0;
    int ret = 0;
    unsigned int nfds = 3;
    struct pollfd fds[3];
    memset(fds, 0, sizeof(fds));

    fds[0].fd = fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    do{
        ret = poll(fds, nfds, -1);
        if(ret <= 0)
        {
            fprintf(stderr, "%s %s:%u - poll failed %d:%s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
            return -1;
        }

        for(i = 0; i < nfds; i++)
        {
            if(fds[i].revents & POLLIN)
            {
                if(fds[i].fd == fd)
                {
                    char ip[32] = {0};
                    unsigned short port = 0;
                    net_fd = tcp_accept(fd, ip, 32, &port);
                    if(net_fd < 0)
                    {
                        fprintf(stderr, "%s %s:%u - 0, tcp_accept %d:%s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
                        goto ErrP;
                    }
                    fprintf(stdout, "%s %s:%u - 0, tcp_accept %s:%hu\n", __FUNCTION__, __FILE__, __LINE__, ip, port);

                    fds[1].fd = net_fd;
                    fds[1].events = POLLIN;
                    fds[1].revents = 0;
                }
                else if(fds[i].fd == net_fd)
                {
                    fds[2].fd = tun_fd[0];
                    fds[2].events = POLLIN;
                    fds[2].revents = 0;

                    net_length = tcp_recv(net_fd, net_buffer, 20);
                    if(net_length <= 0)
                    {
                        fprintf(stderr, "%s %s:%u - 1, tcp_recv fd:%d %d:%s\n", __FUNCTION__, __FILE__, __LINE__, net_fd, errno, strerror(errno));
                        goto ErrP;
                    }
                #ifdef __DEBUG__
                    fprintf(stdout, "%s %s:%u - 1, tcp_recv %d:%s\n", __FUNCTION__, __FILE__, __LINE__, net_length, net_buffer);
                #endif

                    struct iphdr *ip_hdr = (struct iphdr*)net_buffer;
                    uint8_t ip_hdrlen = ip_hdr->ihl*4;
                    uint16_t ip_totlen = ntohs(ip_hdr->tot_len);
                    if(ip_hdrlen != 20 || ip_totlen > 1500)
                    {
                        fprintf(stderr, "%s %s:%u - ip_hdrlen: %hhu, ip_totlen: %hu\n", __FUNCTION__, __FILE__, __LINE__, ip_hdrlen, ip_totlen);
                        goto ErrP;
                    }
                    while(net_length < ip_totlen)
                    {
                        rv = tcp_recv_ready(net_fd, net_buffer+net_length, ip_totlen-net_length, TCP_TIMEOUT);
                        if(rv <= 0)
                        {
                            fprintf(stderr, "%s %s:%u - 1, tcp_recv fd:%d %d:%s\n", __FUNCTION__, __FILE__, __LINE__, net_fd, errno, strerror(errno));
                            goto ErrP;
                        }
                        net_length += rv;
                    #ifdef __DEBUG__
                        fprintf(stdout, "%s %s:%u - 1, tcp_recv %d:%s\n", __FUNCTION__, __FILE__, __LINE__, rv, net_buffer+net_length);
                    #endif
                    }
                #ifdef __DEBUG__
                    PRINT_HEX(net_buffer, net_length);
                #endif

                    rv = tun_write(tun_fd[0], net_buffer, net_length);
                    if(rv != net_length)
                    {
                        fprintf(stderr, "%s %s:%u - 2, tun_write fd:%d %d:%s\n", __FUNCTION__, __FILE__, __LINE__, tun_fd[0], errno, strerror(errno));
                        goto ErrP;
                    }
                #ifdef __DEBUG__
                    fprintf(stdout, "%s %s:%u - 2, tun_write %d:%s\n", __FUNCTION__, __FILE__, __LINE__, net_length, net_buffer);
                    PRINT_HEX(net_buffer, net_length);
                #endif
                }
                else if(fds[i].fd == tun_fd[0])
                {
                    tun_length = tun_read(tun_fd[0], tun_buffer, MAX_BUFFER_SIZE);
                    if(tun_length <= 0)
                    {
                        fprintf(stderr, "%s %s:%u - 3, tun_read fd:%d %d:%s\n", __FUNCTION__, __FILE__, __LINE__, tun_fd[0], errno, strerror(errno));
                        goto ErrP;
                    }
                #ifdef __DEBUG__
                    fprintf(stdout, "%s %s:%u - 3, tun_read %d:%s\n", __FUNCTION__, __FILE__, __LINE__, tun_length, tun_buffer);
                    PRINT_HEX(tun_buffer, tun_length);
                #endif

                    rv = tcp_send(net_fd, tun_buffer, tun_length);
                    if(rv != tun_length)
                    {
                        fprintf(stderr, "%s %s:%u - 4, tcp_send fd:%d %d:%s\n", __FUNCTION__, __FILE__, __LINE__, net_fd, errno, strerror(errno));
                        goto ErrP;
                    }
                #ifdef __DEBUG__
                    fprintf(stdout, "%s %s:%u - 4, tcp_send %d:%s\n", __FUNCTION__, __FILE__, __LINE__, tun_length, tun_buffer);
                    PRINT_HEX(tun_buffer, tun_length);
                #endif
                }
            }
        }
    }while(1);

    tcp_close(fd);
    tcp_close(net_fd);
    tun_close(tun_fd, MAX_QUEUE_NUM);
    return 0;
ErrP:
    tcp_close(fd);
    tcp_close(net_fd);
    tun_close(tun_fd, MAX_QUEUE_NUM);
    return -1;
}
