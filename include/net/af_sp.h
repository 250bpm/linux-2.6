#ifndef __LINUX_NET_AFSP_H
#define __LINUX_NET_AFSP_H

#include <linux/socket.h>
#include <linux/sp.h>
#include <net/sock.h>

#ifdef __KERNEL__
/* The AF_SP socket */
struct sp_sock {
        /* WARNING: sk has to be the first member */
        struct sock	sk;
};
#endif

#endif
