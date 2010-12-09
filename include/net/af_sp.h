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

/* A single peer connection */
struct sp_peer {
	/* The peer socket */
	struct socket *s;
	/* Received message in progress */
        unsigned char *recv_buf;
	/* Received message size */
	size_t recv_size;
	/* Decoder state */
        int recv_state;
};

#define RSTATE_MSGSTART 1
#define RSTATE_MSGDATA 2
#define RSTATE_MSGREADY 3

/* The AF_SP socket private data */
struct sp_sock {
        /* WARNING: sk has to be the first member */
        struct sock	sk;
	/* Pollset */
	struct poll_wqueues pollset;
        /* Socket synchronization mutex */
        struct mutex sync_mutex;
	/* Peer connection */
	struct sp_peer *peer;
};

/* Accessor for sp_sock from generic socket */
#define sp_sk(__sk) ((struct sp_sock *)__sk)

#endif

#endif
