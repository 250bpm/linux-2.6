/*
 * SP: An implementation of SP sockets.
 *
 * Copyright 2011 VMware, Inc.
 */

#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/slab.h>

struct sp_trie
{
	int refcnt;
	unsigned char min;
	unsigned short count;
	union {
		struct sp_trie *node;
		struct sp_trie **table;
	} next;
};

void sp_trie_init (struct sp_trie *trie)
{
	trie->refcnt = 0;
	trie->min = 0;
	trie->count = 0;
}

void sp_trie_destroy (struct sp_trie *trie)
{
	/* TODO: This is a recursive algorithm, remake it into iterative one. */

	unsigned short i;

	if (trie->count == 1)
		sp_trie_destroy (trie->next.node);

	else if (trie->count > 1) {
		for (i = 0; i != trie->count; ++i)
			if (trie->next.table [i])
				sp_trie_destroy (trie->next.table [i]);
		kfree (trie->next.table);
	}

	kfree (trie);
}

void sp_trie_add (struct sp_trie *trie, unsigned char *prefix, int size)
{
	/* TODO: This is a recursive algorithm, remake it into iterative one. */

	unsigned char c, oldc;
        struct sp_trie *oldp, **new_table;
	unsigned short i;
	int old_count;

	/* We are at the node corresponding to the prefix. We are done. */
	if (!size) {
		trie->refcnt++;
		return;
	}

	c = *prefix;
	if (c < trie->min || c >= trie->min + trie->count) {

		/* The character is out of range of currently handled */
                /*characters. We have to extend the table. */
		if (!trie->count) {
			trie->min = c;
			trie->count = 1;
			trie->next.node = NULL;
		}
		else if (trie->count == 1) {
			oldc = trie->min;
			oldp = trie->next.node;
			trie->count = (trie->min < c ? c - trie->min :
				trie->min - c) + 1;
			trie->next.table = (struct sp_trie**)
				kmalloc (sizeof(struct sp_trie*) * trie->count,
					GFP_KERNEL);
			BUG_ON (trie->next.table == NULL);
			for (i = 0; i != trie->count; ++i)
				trie->next.table [i] = 0;
			trie->min = trie->min < c ? trie->min : c;
			trie->next.table [oldc - trie->min] = oldp;
		}
	        else if (trie->min < c) {

			/* The new character is above the current */
                        /* character range. */
			old_count = trie->count;
			trie->count = c - trie->min + 1;
			new_table = (struct sp_trie**)
				kmalloc (sizeof(struct sp_trie*) * trie->count,
					GFP_KERNEL);
			BUG_ON (new_table == NULL);
			memcpy(new_table, trie->next.table,
				sizeof(struct sp_trie*) * old_count);
			kfree (trie->next.table);
			trie->next.table = new_table;
			for (i = old_count; i != trie->count; i++)
				trie->next.table [i] = NULL;
		}
		else {

			/* The new character is below the current */
			/* character range. */
			old_count = trie->count;
			trie->count = (trie->min + old_count) - c;
			new_table = (struct sp_trie**)
				kmalloc (sizeof(struct sp_trie*) * trie->count,
					GFP_KERNEL);
			BUG_ON (new_table == NULL);
			memcpy(new_table + trie->min - c, trie->next.table,
				sizeof(struct sp_trie*) * old_count);
			kfree (trie->next.table);
			for (i = 0; i != trie->min - c; i++)
				trie->next.table [i] = NULL;
			trie->min = c;
		}
	}

	/* If next node does not exist, create one. */
	if (trie->count == 1) {
		if (!trie->next.node) {
			trie->next.node = kmalloc(sizeof(struct sp_trie),
				GFP_KERNEL);
			BUG_ON(trie->next.node == NULL);
		}
		sp_trie_add(trie->next.node, prefix + 1, size - 1);
	}
	else {
		if (!trie->next.table[c - trie->min]) {
			trie->next.table[c - trie->min] =
				kmalloc(sizeof(struct sp_trie), GFP_KERNEL);
			BUG_ON(trie->next.table[c - trie->min]);
		}
		sp_trie_add(trie->next.table[c - trie->min],
			prefix + 1, size - 1);
	}
}

int sp_trie_rm (struct sp_trie *trie, unsigned char *prefix, int size)
{
	/* TODO: This is a recursive algorithm, remake it into iterative one. */

	unsigned char c;
	struct sp_trie *next_node;

	if (!size) {
		if (!trie->refcnt)
			return -EINVAL;
		trie->refcnt--;
		return 0;
	}

	c = *prefix;
	if (!trie->count || c < trie->min || c >= trie->min + trie->count)
		return -EINVAL;

	next_node = trie->count == 1 ?
		trie->next.node : trie->next.table [c - trie->min];

	if (!next_node)
		return -EINVAL;

	return sp_trie_rm (next_node, prefix + 1, size - 1);
}

int sp_trie_check (struct sp_trie *trie, unsigned char *data, int size)
{
	unsigned char c;

	while (true) {

		/* We've found a corresponding subscription! */
		if (trie->refcnt)
			return 1;

		/* We've checked all the data and haven't found */
		/* matching subscription. */
		if (!size)
			return 0;

		/* If there's no corresponding slot for the first character */
		/*  of the prefix, the message does not match. */
		c = *data;
		if (c < trie->min || c >= trie->min + trie->count)
			return 0;

		/* Move to the next character. */
		if (trie->count == 1)
			trie = trie->next.node;
		else {
			trie = trie->next.table [c - trie->min];
			if (!trie)
				return 0;
		}
		data++;
		size--;
	}
}
