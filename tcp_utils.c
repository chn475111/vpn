#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/version.h>
#include "tcp_utils.h"

int set_block_option(int fd)
{
    struct linger lg = {
        .l_onoff = 1,
        .l_linger = 0
    };
    struct timeval tv = {
        .tv_sec = 3,
        .tv_usec = 0
    };

    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(struct linger));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
    return fd;
}

int set_nonblock_option(int fd)
{
    struct linger lg = {
        .l_onoff = 1,
        .l_linger = 0
    };

    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(struct linger));
    return fd;
}

int tcp_socket()
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(fd < 0)
        return fd;

    set_block_option(fd);
    return fd;
}

int tcp_bind(int fd, char *ip, unsigned short port)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    int flag = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(int));
#endif
    return bind(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
}

int tcp_listen(int fd, int backlog)
{
    int timeout = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, sizeof(int));
    return listen(fd, backlog);
}

int tcp_accept(int sockfd, char *ip, int iplen, unsigned short *port)
{
    int fd = 0;
    socklen_t len = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));

    do{
        fd = accept(sockfd, (struct sockaddr*)&addr, &len);
        if(fd != -1)
            break;
    }while(0);

    if(fd < 0)
        return fd;

    if(ip && iplen > 0) snprintf(ip, iplen, "%s", inet_ntoa(addr.sin_addr));
    if(port) *port = ntohs(addr.sin_port);

    set_block_option(fd);
    return fd;
}

int tcp_connect(int fd, char *ip, unsigned short port)
{
    int ret = 0;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    do{
        ret = connect(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
        if(ret != -1)
            break;
    #if 1
        if(errno == EINPROGRESS)
            ret = tcp_connect_ready(fd, 3000);
    #endif
    }while(0);

    return ret;
}

int tcp_connect_ready(int fd, int timeout)
{
    int ret = 0;
    int optval = -1;
    socklen_t optlen = sizeof(int);

    int i = 0;
    unsigned int nfds = 1;
    struct pollfd fds[1] = {
        [0] = {
            .fd = fd,
            .events = POLLOUT,
            .revents = 0
        }
    };

    do{
        ret = poll(fds, nfds, timeout);
        if(ret <= 0)
        {
            fprintf(stderr, "%s %s:%u - poll failed %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
            return -1;
        }
    }while(0);

    for(i = 0; i < nfds; i++)
    {
        if(fds[i].revents & POLLOUT)
        {
            if(fds[i].fd == fd)
            {
                ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, &optlen);
                if(ret != 0 || optval != 0)
                {
                    fprintf(stderr, "%s %s:%u - getsockopt failed %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
                    return -1;
                }
            }
        }
    }

    return 0;
}

int tcp_send(int fd, unsigned char *buf, int len)
{
    int send_len = 0, send_tmp = 0;

    do{
        send_tmp = send(fd, buf+send_len, len-send_len, 0);
        if(send_tmp < 0)
            return send_tmp;

        send_len += send_tmp; 
    }while(0);

    return send_len;
}

int tcp_recv(int fd, unsigned char *buf, int len)
{
    int recv_len = 0, recv_tmp = 0;

    do{
        recv_tmp = recv(fd, buf+recv_len, len-recv_len, 0);
        if(recv_tmp <= 0)
            return recv_tmp;

        recv_len += recv_tmp;
    }while(0);

    return recv_len;
}

int tcp_recv_ready(int fd, unsigned char *buf, int len, int timeout)
{
    int i = 0;
    int ret = 0;
    unsigned int nfds = 1;
    struct pollfd fds[1] = {
        [0] = {
            .fd = fd,
            .events = POLLIN,
            .revents = 0
        }
    };

    ret = poll(fds, nfds, timeout);
    if(ret <= 0)
    {
        fprintf(stderr, "%s %s:%u - poll failed %d: %s\n", __FUNCTION__, __FILE__, __LINE__, errno, strerror(errno));
        return -1;
    }

    for(i = 0; i < nfds; i++)
    {
        if(fds[i].revents & POLLIN)
        {
            if(fds[i].fd == fd) return tcp_recv(fd, buf, len);
        }
    }

    return -1;
}

void tcp_close(int fd)
{
    if(fd > 0)
    {
        shutdown(fd, 1);
        close(fd);
    }
}

int get_peer_ip_and_port(int fd, char *ip, int iplen, unsigned short *port)
{
    int ret = 0;
    socklen_t len = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));

    ret = getpeername(fd, (struct sockaddr*)&addr, &len);
    if(ret == 0)
    {
        if(ip && iplen>0) snprintf(ip, iplen, "%s", inet_ntoa(addr.sin_addr));
        if(port) *port = ntohs(addr.sin_port);
    }

    return ret;
}

int get_local_ip_and_port(int fd, char *ip, int iplen, unsigned short *port)
{
    int ret = 0;
    socklen_t len = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));

    ret = getsockname(fd, (struct sockaddr*)&addr, &len);
    if(ret == 0)
    {
        if(ip && iplen>0) snprintf(ip, iplen, "%s", inet_ntoa(addr.sin_addr));
        if(port) *port = ntohs(addr.sin_port);
    }

    return ret;
}
