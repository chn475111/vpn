#ifndef __TCP_UTILS_H__
#define __TCP_UTILS_H__

#define TCP_TIMEOUT 3000

int set_block_option(int fd);

int set_nonblock_option(int fd);

int tcp_socket();

int tcp_bind(int fd, char *ip, unsigned short port);

int tcp_listen(int fd, int backlog);

int tcp_accept(int sockfd, char *ip, int iplen, unsigned short *port);

int tcp_connect(int fd, char *ip, unsigned short port);

int tcp_connect_ready(int fd, int timeout);

int tcp_send(int fd, unsigned char *buf, int len);

int tcp_recv(int fd, unsigned char *buf, int len);

int tcp_recv_ready(int fd, unsigned char *buf, int len, int timeout);

void tcp_close(int fd);

int get_peer_ip_and_port(int fd, char *ip, int iplen, unsigned short *port);

int get_local_ip_and_port(int fd, char *ip, int iplen, unsigned short *port);

#endif
