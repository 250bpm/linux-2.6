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
	/* The inbound message being received at the moment */
        void *inmsg_data;
        int inmsg_size;
        int inmsg_pos;
};

/* The AF_SP socket private data */
struct sp_sock {
        /* WARNING: sk has to be the first member */
        struct sock sk;
        /* Lists of underlying sockets */
        struct list_head listeners;
        struct list_head connections;
};

#endif

#endif
