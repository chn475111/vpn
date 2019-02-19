#ifndef _TUN_H_
#define _TUN_H_

#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/route.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netdevice.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
    #define MAX_QUEUE_NUM 1
#else
    #define MAX_QUEUE_NUM 8
#endif

#define TUN_DEV "/dev/net/tun"
#define TUN_TIMEOUT 3000

int tun_add_route(char *net, char *mask, char *gw, char *dev);

int tun_del_route(char *net, char *mask, char *gw, char *dev);

int tun_open(char *name, char *ip, char *mask, int fd_arr[], int fd_sum);

int tun_write(int fd, unsigned char *buf, int len);

int tun_read(int fd, unsigned char *buf, int len);

void tun_close(int fd_arr[], int fd_sum);

#endif
