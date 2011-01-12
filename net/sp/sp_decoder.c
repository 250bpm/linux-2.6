
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <net/sp_decoder.h>

static inline u64 sp_read_u64 (u8 *buff);
static void sp_decoder_alloc_message(struct sp_decoder *dcdr, int size);

/* State machine actions */
static void sp_decoder_idle(struct sp_decoder *dcdr);
static void sp_decoder_one_byte_size_ready(struct sp_decoder *dcdr);
static void sp_decoder_eight_byte_size_ready(struct sp_decoder *dcdr);
static void sp_decoder_flags_ready(struct sp_decoder *dcdr);
static void sp_decoder_data_ready(struct sp_decoder *dcdr);

/*
 * Reads 64-bit unsigned integer from buffer in network byte order
 */
static inline u64 sp_read_u64 (u8 *buff)
{
	return
		(((u64) buff[0]) << 56) |
		(((u64) buff[1]) << 48) |
		(((u64) buff[2]) << 40) |
		(((u64) buff[3]) << 32) |
		(((u64) buff[4]) << 24) |
		(((u64) buff[5]) << 16) |
		(((u64) buff[6]) << 8) |
		((u64) buff[7]);
}

/*
 * Initialise the SP decoder
 */
void sp_decoder_init(struct sp_decoder *dcdr,
	int (*read)(struct sp_decoder*, void*, int))
{
	dcdr->read = read;
	dcdr->next = sp_decoder_idle;
	dcdr->read_pos = NULL;
	dcdr->read_size = 0;
	dcdr->msg_data = NULL;
	dcdr->msg_size = 0;
	dcdr->msg_ready = 0;
}

/*
 * Uninitialise the SP decoder
 */
void sp_decoder_destroy(struct sp_decoder *dcdr)
{
	if (dcdr->msg_data)
		kfree(dcdr->msg_data);
}

int sp_decoder_get_message(struct sp_decoder *dcdr, int maxsize,
	void **data, int *size)
{
	int n;

	while(1) {

		/* If there is a message available return it */
		if(dcdr->msg_ready) {

			if(dcdr->msg_size > maxsize)
				return -EMSGSIZE;

			*data = dcdr->msg_data;
			*size = dcdr->msg_size;
			dcdr->msg_data = NULL;
			dcdr->msg_size = 0;
			dcdr->msg_ready = 0;
			return 0;
		}

		/* If there is no more data to read invoke the state machine */
		if(dcdr->read_size == 0)
			dcdr->next(dcdr);

		/* Try to read as much data as required by the state machine */
		n = dcdr->read(dcdr, dcdr->read_pos, dcdr->read_size);
		dcdr->read_pos += n;
		dcdr->read_size -= n;

		/* If not all data requested was read we have to wait */
		if (dcdr->read_size)
			return -EAGAIN;
	}
}

/*
 * Allocates a new message of a specified size
 */
static void sp_decoder_alloc_message(struct sp_decoder *dcdr, int size)
{
	dcdr->msg_data = kmalloc(size, GFP_KERNEL);
	BUG_ON(!dcdr->msg_data);
	dcdr->msg_size = size;

	dcdr->read_pos = dcdr->buff;
	dcdr->read_size = 1;
	dcdr->next = sp_decoder_flags_ready;
}

static void sp_decoder_idle(struct sp_decoder *dcdr)
{
	dcdr->read_pos = dcdr->buff;
	dcdr->read_size = 1;
	dcdr->next = sp_decoder_one_byte_size_ready;
}

static void sp_decoder_one_byte_size_ready(struct sp_decoder *dcdr)
{
	u8 size = dcdr->buff[0];

	if(size == 0xff) {
		dcdr->read_pos = dcdr->buff;
		dcdr->read_size = 8;
		dcdr->next = sp_decoder_eight_byte_size_ready;
		return;
	}

	sp_decoder_alloc_message(dcdr, size);
}

static void sp_decoder_eight_byte_size_ready(struct sp_decoder *dcdr)
{
	int size = (int) sp_read_u64(dcdr->buff);
	sp_decoder_alloc_message(dcdr, size);
}

static void sp_decoder_flags_ready(struct sp_decoder *dcdr)
{
	/* Ignore the flags for now and continue on */
	dcdr->read_pos = dcdr->msg_data;
	dcdr->read_size = dcdr->msg_size;
	dcdr->next = sp_decoder_data_ready;
}

static void sp_decoder_data_ready(struct sp_decoder *dcdr)
{
	dcdr->msg_ready = 1;

	dcdr->read_pos = NULL;
	dcdr->read_size = 0;
	dcdr->next = sp_decoder_idle;
}
