/*
 * SP: An implementation of SP sockets.
 *
 * Copyright 2010 VMware, Inc.
 */

#ifndef __LINUX_NET_AFSP_H
#define __LINUX_NET_AFSP_H

#include <linux/socket.h>
#include <linux/list.h>
#include <linux/sp.h>
#include <net/sock.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <net/sp_decoder.h>
#include <net/sp_encoder.h>

#ifdef __KERNEL__

/* A single underlying socket */
struct sp_usock {
        /* Each SP socket has a list of usocks */
        struct list_head list;
        /* The SP socket owning this underlying socket */
        struct sp_sock *owner;
	/* The underlying socket itself */
	struct socket *s;
        /* Work performed on behalf of this socket */
        struct work_struct work_in;
        struct work_struct work_out;
	/* The decoder to process inbound messages */
	struct sp_decoder decoder;
	/* The encoder to process outbound messages */
	struct sp_encoder encoder;
};

/* The AF_SP socket private data */
struct sp_sock {
        /* WARNING: sk has to be the first member */
        struct sock sk;
        /* Lists of underlying sockets */
        struct list_head listeners;
        struct list_head connections;
	/* Mutex to synchronise user-space threads with kernel workqueues */
	struct mutex sync;
	/* Completion to wait on in send calls */
	struct completion send_wait;
	/* If 1 user thread is being blocked on send */
	int send_waiting;
	/* Completion to wait on in recv calls */
	struct completion recv_wait;
	/* If 1 user thread is being blocked on recv */
	int recv_waiting;
};

#endif

#endif
