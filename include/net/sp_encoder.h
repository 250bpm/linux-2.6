/*
 * SP: An implementation of SP sockets.
 *
 * Copyright 2010 VMware, Inc.
 */

#ifndef __LINUX_NET_SP_ENCODER_H
#define __LINUX_NET_SP_ENCODER_H

#include <linux/types.h>
#include <linux/socket.h>

struct sp_encoder
{
	/* Function to send the encoded data */
	int (*write)(struct sp_encoder *ecdr, void *data, int size);

	/* State of the finite state machine */
	void (*next)(struct sp_encoder *ecdr);
	void *write_pos;
	int write_size;

	/* The message being sent */
	void *msg_data;
	int msg_size;
	int msg_sent;

	/* Temporary buffer */
	u8 buff[10];
};

void sp_encoder_init(struct sp_encoder *ecdr,
	int (*write)(struct sp_encoder*, void*, int));
void sp_encoder_destroy(struct sp_encoder *ecdr);
int sp_encoder_put_message(struct sp_encoder *ecdr, struct msghdr *hdr,
	int len);
void sp_encoder_flush(struct sp_encoder *ecdr);

#endif
