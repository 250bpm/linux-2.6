/*
 * SP: An implementation of SP sockets.
 *
 * Copyright 2010 VMware, Inc.
 */

#ifndef __LINUX_NET_SP_DECODER_H
#define __LINUX_NET_SP_DECODER_H

#include <linux/types.h>

struct sp_decoder
{
	/* Function to get more data to decode */
	int (*read)(struct sp_decoder *dcdr, void *data, int size);

	/* State of the finite state machine */
	void (*next)(struct sp_decoder*);
	void *read_pos;
	int read_size;

	/* The message being read */
	void *msg_data;
	int msg_size;
	int msg_ready;

	/* Temporary buffer */
	u8 buff[8];
};

void sp_decoder_init(struct sp_decoder *dcdr,
	int (*read)(struct sp_decoder*, void*, int));
void sp_decoder_destroy(struct sp_decoder *dcdr);
int sp_decoder_get_message(struct sp_decoder *dcdr, int maxsize,
	void **data, int *size);

#endif
