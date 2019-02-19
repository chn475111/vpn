#define _GNU_SOURCE
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "log.h"
#include "tun_utils.h"

int tun_set_block(int fd)
{
    struct timeval tv = {
        .tv_sec = 3,
        .tv_usec = 0
    };
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
    return fd;
}

int tun_set_nonblock(int fd)
{
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
    return fd;
}

int tun_set_dev(int fd, struct ifreq *ifr)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
    ifr->ifr_flags = IFF_TUN | IFF_NO_PI;
#else
    ifr->ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
#endif

    if (ioctl(fd, TUNSETIFF, ifr) != 0)
    {
        log_err("set tun %s dev failed: %m", ifr->ifr_name);
        return -1;
    }
    return 0;
}

int tun_set_status(int fd, struct ifreq *ifr)
{
    ifr->ifr_flags = IFF_UP | IFF_RUNNING;

    if (ioctl(fd, SIOCSIFFLAGS, ifr) != 0)
    {
        log_err("set tun %s status failed: %m", ifr->ifr_name);
        return -1;
    }
    return 0;
}

int tun_set_ip(int fd, struct ifreq *ifr, char *ip)
{
    struct sockaddr_in *addr;
    
    addr = (struct sockaddr_in *)&(ifr->ifr_addr);
    addr->sin_family = AF_INET;
    inet_aton(ip, &(addr->sin_addr));

    if (ioctl(fd, SIOCSIFADDR, ifr) != 0)
    {
        log_err("set tun %s ip addr to %s failed: %m", ifr->ifr_name, ip);
        return -1;
    }
    return 0;
}

int tun_set_mask(int fd, struct ifreq *ifr, char *mask)
{
    struct sockaddr_in *addr;
    
    addr = (struct sockaddr_in *)&(ifr->ifr_addr);
    addr->sin_family = AF_INET;
    inet_aton(mask, &(addr->sin_addr));

    if (ioctl(fd, SIOCSIFNETMASK, ifr) != 0)
    {
        log_err("set tun %s netmask to %s failed: %m", ifr->ifr_name, mask);
        return -1;
    }
    return 0;
}

int tun_add_route(char *net, char *mask, char *gw, char *dev)
{
    struct rtentry rt;
    struct sockaddr_in *addr;

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 
    if(fd < 0)
    {
        log_err("open udp socket failed: %m");
        return -1;
    }
    memset(&rt, 0, sizeof(rt));

    addr = (struct sockaddr_in *)&rt.rt_dst;
    addr->sin_family = AF_INET;
    inet_aton(net, &(addr->sin_addr));

    addr = (struct sockaddr_in *)&rt.rt_genmask;
    addr->sin_family = AF_INET;
    inet_aton(mask, &(addr->sin_addr));

    addr = (struct sockaddr_in *)&rt.rt_gateway;
    addr->sin_family = AF_INET;
    inet_aton(gw, &(addr->sin_addr));

    rt.rt_dev = dev;
    rt.rt_flags = RTF_UP | RTF_GATEWAY;

    if (ioctl(fd, SIOCADDRT, &rt) != 0)
    {
        log_err("route add -net %s netmask %s via %s dev %s - failed: %m", net, mask, gw, dev);
        if(fd > 0) close(fd);
        return -1;
    }
    if(fd > 0) close(fd);
    return 0;
}

int tun_del_route(char *net, char *mask, char *gw, char *dev)
{
    struct rtentry rt;
    struct sockaddr_in *addr;

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 
    if(fd < 0)
    {
        log_err("open udp socket failed: %m");
        return -1;
    }
    memset(&rt, 0, sizeof(rt));

    addr = (struct sockaddr_in *)&rt.rt_dst;
    addr->sin_family = AF_INET;
    inet_aton(net, &(addr->sin_addr));

    addr = (struct sockaddr_in *)&rt.rt_genmask;
    addr->sin_family = AF_INET;
    inet_aton(mask, &(addr->sin_addr));

    addr = (struct sockaddr_in *)&rt.rt_gateway;
    addr->sin_family = AF_INET;
    inet_aton(gw, &(addr->sin_addr));

    rt.rt_dev = dev;
    rt.rt_flags = RTF_UP | RTF_GATEWAY;

    if (ioctl(fd, SIOCDELRT, &rt) != 0)
    {
        log_err("route del -net %s netmask %s via %s dev %s - failed: %m", net, mask, gw, dev);
        if(fd > 0) close(fd);
        return -1;
    }
    if(fd > 0) close(fd);
    return 0;
}

int tun_open(char *name, char *ip, char *mask, int fd_arr[], int fd_sum)
{
    int i = 0;
    int fd = 0;
    int sockfd = 0;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    fd_sum = fd_sum < MAX_QUEUE_NUM ? fd_sum : MAX_QUEUE_NUM;
    for(i = 0; i < fd_sum; i ++)
    {   fd = open(TUN_DEV, O_RDWR);
        if (fd < 0)
        {
            log_err("open tun %s failed: %m", TUN_DEV);
            return -1;
        }
        if (tun_set_dev(fd, &ifr) != 0)
            goto ErrP;

        fd_arr[i] = tun_set_block(fd);
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 
    if(sockfd < 0)
    {
        log_err("open udp socket failed: %m");
        goto ErrP;
    }

    if (tun_set_status(sockfd, &ifr) != 0)
        goto ErrP;

    if (tun_set_ip(sockfd, &ifr, ip) != 0)
        goto ErrP;

    if (tun_set_mask(sockfd, &ifr, mask) != 0)
        goto ErrP;

    log_debug("tun %s was opened", name);
    if(sockfd > 0) close(sockfd);
    return fd_sum;
ErrP:
    tun_close(fd_arr, fd_sum);
    if(sockfd > 0) close(sockfd);
    return -1;
}

int tun_write(int fd, unsigned char *buf, int len)
{
    int write_len = 0, write_tmp = 0;

    do{
        write_tmp = write(fd, buf+write_len, len-write_len);
        if(write_tmp < 0)
            return write_tmp;

        write_len += write_tmp; 
    }while(0);

    return write_len;
}

int tun_read(int fd, unsigned char *buf, int len)
{
    int read_len = 0, read_tmp = 0;

    do{
        read_tmp = read(fd, buf+read_len, len-read_len);
        if(read_tmp <= 0)
            return read_tmp;

        read_len += read_tmp;
    }while(0);

    return read_len;
}

int tun_read_ready(int fd, unsigned char *buf, int len, int timeout)
{
    int i = 0;
    int ret = 0;
    unsigned int nfds = 1;
    struct pollfd fds[1];
    fds[0].fd = fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    ret = poll(fds, nfds, timeout);
    if(ret <= 0)
    {
        log_err("poll failed - %d: %s\n", errno, strerror(errno));
        return -1;
    }

    for(i = 0; i < nfds; i++)
    {
        if(fds[i].revents & POLLIN)
        {
            if(fds[i].fd == fd) return tun_read(fd, buf, len);
        }
    }

    return -1;
}

void tun_close(int fd_arr[], int fd_sum)
{
    int i;
    for(i = 0; i < fd_sum; i ++)
    {
        if (fd_arr[i] > 0)
        {
            log_debug("tun fd %d was closed", fd_arr[i]);
            close(fd_arr[i]);
        }
    }
}
