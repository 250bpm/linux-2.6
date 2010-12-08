/*
 * SP: An implementation of SP sockets.
 *
 * Copyright 2010 VMware, Inc.
 */

#ifndef __LINUX_NET_AFSP_H
#define __LINUX_NET_AFSP_H

#include <linux/socket.h>
#include <linux/sp.h>
#include <net/sock.h>

#ifdef __KERNEL__

/* The AF_SP socket private data */
struct sp_sock {
        /* WARNING: sk has to be the first member */
        struct sock	sk;
	/* Peer socket */
	struct socket	*peer;
	/* Pollset */
	struct poll_wqueues pollset;
};

/* Accessor for sp_sock from generic socket */
#define sp_sk(__sk) ((struct sp_sock *)__sk)

#endif

#endif
