/*
 * SP: An implementation of SP sockets.
 *
 * Copyright 2010 VMware, Inc.
 */

#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <net/sp_encoder.h>

/* State machine actions */
static void sp_encoder_idle(struct sp_encoder *ecdr);
static void sp_encoder_size_and_flags_ready(struct sp_encoder *ecdr);
static void sp_encoder_data_ready(struct sp_encoder *ecdr);

/*
 * Writes 64-bit unsigned integer to buffer in network byte order
 */
static inline void sp_write_u64 (u8 *buff, u64 value)
{
	buff[0] = (u8) (((value) >> 56) & 0xff);
	buff[1] = (u8) (((value) >> 48) & 0xff);
	buff[2] = (u8) (((value) >> 40) & 0xff);
	buff[3] = (u8) (((value) >> 32) & 0xff);
	buff[4] = (u8) (((value) >> 24) & 0xff);
	buff[5] = (u8) (((value) >> 16) & 0xff);
	buff[6] = (u8) (((value) >> 8) & 0xff);
	buff[7] = (u8) (value & 0xff);
}

void sp_encoder_init(struct sp_encoder *ecdr,
	int (*write)(struct sp_encoder*, void*, int))
{
	ecdr->write = write;
	ecdr->next = sp_encoder_idle;
	ecdr->write_pos = NULL;
	ecdr->write_size = 0;
	ecdr->msg_data = NULL;
	ecdr->msg_size = 0;
	ecdr->msg_sent = 1;
}

void sp_encoder_destroy(struct sp_encoder *ecdr)
{
	if(ecdr->msg_data)
		kfree(ecdr->msg_data);
}

int sp_encoder_put_message(struct sp_encoder *ecdr, struct msghdr *msg, int len)
{
	int rc = 0;

	/* If there's still message being sent return error */
	if(!ecdr->msg_sent)
		return -EAGAIN;

	/* Create a buffer from the message */
	ecdr->msg_data = kmalloc(len, GFP_KERNEL);
	if (!ecdr->msg_data) {
		rc = -ENOMEM;
		goto out;
	}

	/* Copy the message to the buffer */
	rc = memcpy_fromiovec(ecdr->msg_data, msg->msg_iov, len);
	if (rc < 0) 
		goto out_dealloc;
	ecdr->msg_size = len;
	ecdr->msg_sent = 0;

	/* Try to flush the message to the network */
	ecdr->next = sp_encoder_idle;
	sp_encoder_flush(ecdr);

	goto out;

out_dealloc:
	kfree(ecdr->msg_data);
	ecdr->msg_data = NULL;
out:
	return rc;
}

void sp_encoder_flush(struct sp_encoder *ecdr)
{
	int n;

	for(;;) {

		/* If there's no data available exit */
		if (!ecdr->write_size)
			break;

		/* Try to send the remaining data */
		n = ecdr->write(ecdr, ecdr->write_pos, ecdr->write_size);
		ecdr->write_pos += n;
		ecdr->write_size -= n;

		/* If more data cannot be sent exit */
		if(ecdr->write_size)
			break;

		/* If there's no more data available run the state machine */
		ecdr->next(ecdr);
	}
}

static void sp_encoder_idle(struct sp_encoder *ecdr)
{
	if (ecdr->msg_size < 0xff) {
		ecdr->buff[0] = (u8)ecdr->msg_size;
		ecdr->buff[1] = 0;
		ecdr->write_pos = ecdr->buff;
		ecdr->write_size = 2;
		ecdr->next = sp_encoder_size_and_flags_ready;
		return;
	}

	ecdr->buff[0] = 0xff;
	sp_write_u64(ecdr->buff + 1, ecdr->msg_size);
	ecdr->buff[9] = 0;
	ecdr->write_pos = ecdr->buff;
	ecdr->write_size = 10;
	ecdr->next = sp_encoder_size_and_flags_ready;
}

static void sp_encoder_size_and_flags_ready(struct sp_encoder *ecdr)
{
	ecdr->write_pos = ecdr->msg_data;
	ecdr->write_size = ecdr->msg_size;
	ecdr->next = sp_encoder_data_ready;
}

static void sp_encoder_data_ready(struct sp_encoder *ecdr)
{
	if (ecdr->msg_data)
		kfree(ecdr->msg_data);

	ecdr->write_pos = NULL;
	ecdr->write_size = 0;
	ecdr->next = sp_encoder_idle;
}
