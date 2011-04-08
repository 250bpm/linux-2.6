/*
 * SP: An implementation of SP sockets.
 *
 * Copyright 2010 VMware, Inc.
 *
 * Authors: Martin Sustrik <sustrik@250bpm.com>
 *	    Martin Lucina <mato@kotelna.sk>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/sp.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <net/af_sp.h>
#include <linux/err.h>
#include <linux/in.h>
#include <net/tcp_states.h>

/* Underlying protocol constants */
#define SP_PROTOCOL_TCP 1

static int sp_create(struct net *, struct socket *, int, int);
static void sp_destruct(struct sock *);
static int sp_release(struct socket *sock);
static int sp_connect(struct socket *, struct sockaddr *, int, int);
static int sp_bind(struct socket *, struct sockaddr *, int);
static int sp_sendmsg(struct kiocb *, struct socket *, struct msghdr *, size_t);
static int sp_recvmsg(struct kiocb *, struct socket *, struct msghdr *,
	size_t, int);
static void sp_in_cb(struct sock *sk, int bytes);
static void sp_out_cb(struct sock *sk);
static void sp_listener_work_in(struct work_struct *work);
static void sp_state_cb(struct sock *sk);

/* SP protocol information */
static struct proto sp_proto = {
        .name =         "SP",
        .owner =        THIS_MODULE,
        .obj_size =     sizeof(struct sp_sock),
};

/* SP protocol family operations */
static const struct net_proto_family sp_family_ops = {
	.family =	PF_SP,
	.create =	sp_create,
	.owner =	THIS_MODULE,
};

/* SP SOCK_PUB socket operations */
static const struct proto_ops sp_sock_ops = {
	.family =	PF_SP,
	.owner =	THIS_MODULE,
	.release =	sp_release,
	.bind =		sp_bind,
	.connect =	sp_connect,
	.socketpair =	sock_no_socketpair,
	.accept =	sock_no_accept,
	.getname =	sock_no_getname,
	.poll =		sock_no_poll,
	.ioctl =	sock_no_ioctl,
	.listen =	sock_no_listen,
	.shutdown =	sock_no_shutdown,
	.setsockopt =	sock_no_setsockopt,
	.getsockopt =	sock_no_getsockopt,
	.sendmsg =	sp_sendmsg,
	.recvmsg =	sp_recvmsg,
	.mmap =		sock_no_mmap,
	.sendpage =	sock_no_sendpage,
};

/*
 * sp_usock_read: this function is used by decoder to read more data from
                  the underlying socket
 */
int sp_usock_read(struct sp_decoder *dcdr, void *data, int size)
{
	struct sp_usock *usock = container_of(dcdr, struct sp_usock, decoder);
	struct kvec vec;
	struct msghdr hdr;
	int nbytes;

	memset (&hdr, 0, sizeof hdr);
	vec.iov_base = (char *)data;
	vec.iov_len = size;
	nbytes = kernel_recvmsg(usock->s, &hdr, &vec, 1, vec.iov_len,
		MSG_DONTWAIT);
	printk (KERN_INFO "SP: %s sk=%p size=%d nbytes=%d\n", __func__,
		usock->s->sk, size, nbytes);
	if (nbytes == -EAGAIN)
		return 0;
	BUG_ON(nbytes < 0);
	return nbytes;
}

/*
 * sp_usock_write: this function is used by encoder to write data to
                   the underlying socket
 */
int sp_usock_write(struct sp_encoder *ecdr, void *data, int size)
{
	struct sp_usock *usock = container_of(ecdr, struct sp_usock, encoder);
	struct kvec vec;
	struct msghdr hdr;
	int nbytes;

	memset (&hdr, 0, sizeof hdr);
	hdr.msg_flags = MSG_DONTWAIT;
	vec.iov_base = (char *)data;
	vec.iov_len = size;
	nbytes = kernel_sendmsg(usock->s, &hdr, &vec, 1, vec.iov_len);
	printk (KERN_INFO "SP: %s sk=%p size=%d nbytes=%d\n", __func__,
		usock->s->sk, size, nbytes);
	if (nbytes == -EAGAIN)
		return nbytes;
	/* TODO: Handle -EPIPE */
	BUG_ON(nbytes < 0);
	return nbytes;
}

/*
 * sp_usock_destroy: clean up the underlying socket
 */
static void sp_usock_destroy (struct sp_usock *usock, int sync)
{
	struct sp_sock *owner = usock->owner;

	printk(KERN_INFO "SP: %s owner=%p sk=%p\n", __func__, usock->s->sk,
		usock->owner);

	/* Restore old socket callbacks */
	write_lock_bh(&usock->s->sk->sk_callback_lock);
	usock->s->sk->sk_state_change = usock->old_sk_state_change;
	usock->s->sk->sk_data_ready = usock->old_sk_data_ready;
	usock->s->sk->sk_write_space = usock->old_sk_write_space;
	write_unlock_bh(&usock->s->sk->sk_callback_lock);

	/* Ensure any work items on the socket have completed */
	cancel_work_sync(&usock->work_in);
	cancel_work_sync(&usock->work_out);
	if (sync)
		cancel_work_sync(&usock->work_destroy);

	/* Deallocate the socket */
	mutex_lock(&owner->sync);
	sock_release(usock->s);
	list_del(&usock->list);
	sp_decoder_destroy(&usock->decoder);
	sp_encoder_destroy(&usock->encoder);
	kfree(usock);
	mutex_unlock(&owner->sync);
}

/*
 * sp_parse_address: convert textual address into corresponding structure
 */
static int sp_parse_address (const char *string, int *protocol,
	struct sockaddr_storage *addr, int *addr_len)
{
	int i, seg;
	char *pos;
	struct sockaddr_in *addr_in;

	/* Split the connection string to protocol and address parts */
	/* TODO: check whether strchr doesn't exceed the address length */
	pos = strchr (string, ':');
	if (pos == NULL)
		return -EINVAL;
	pos++;
	if (*pos != '/')
		return -EINVAL;
	pos++;
	if (*pos != '/')
		return -EINVAL;
	pos++;

	if (pos - string == 6 && strncmp(string, "tcp://", 6) == 0) {

		/* TCP */
		*protocol = SP_PROTOCOL_TCP;
		addr_in = (struct sockaddr_in *)addr;
		*addr_len = sizeof(struct sockaddr_in);

		/* First, set the address family */
		addr_in->sin_family = AF_INET;

		/* Parse the "192.168.0.1"-style IP address */
		addr_in->sin_addr.s_addr = 0;
		for(i = 0; i != 4; i++) {
			seg = 0;
		        while(*pos >= '0' && *pos <= '9') {
				seg = seg * 10 + *pos - '0';
				pos++;
				if(seg > 0xff)
					return -EINVAL;
			}
			if(i < 3 && *pos != '.')
				return -EINVAL;
			if(i == 3 && *pos != ':')
				return -EINVAL;
			pos++;
			addr_in->sin_addr.s_addr <<= 8;
			addr_in->sin_addr.s_addr |= seg;
		}
		addr_in->sin_addr.s_addr = htonl (addr_in->sin_addr.s_addr);

		/* Now parse the port number */
		seg = 0;
		while (*pos >= '0' && *pos <= '9') {
			seg = seg * 10 + *pos - '0';
			pos++;
			if (seg > 0xffff)
				return -EINVAL;

		}
		if (*pos != 0)
			return -EINVAL;
		addr_in->sin_port = htons(seg);
	}
	else {
		/* Unsupported underlying protocol */
		return -ENOTSUPP;
	}

	return 0;
}

static void sp_data_work_in(struct work_struct *work)
{
	struct sp_usock *usock = container_of(work,
		struct sp_usock, work_in);

	/* If a user thread is waiting for a message, unblock it */
	mutex_lock(&usock->owner->sync);
	if(usock->owner->recv_waiting) {
		usock->owner->recv_waiting = 0;
		complete(&usock->owner->recv_wait);
	}
	mutex_unlock(&usock->owner->sync);
}

static void sp_data_work_out(struct work_struct *work)
{
	struct sp_usock *usock = container_of(work,
		struct sp_usock, work_out);

	mutex_lock(&usock->owner->sync);

	/* Try to send the remaining part of the message */
	sp_encoder_flush (&usock->encoder);

	/*  If there's user thread waiting, unblock it */
	if(usock->owner->send_waiting) {
		usock->owner->send_waiting = 0;
		complete(&usock->owner->send_wait);
	}

	mutex_unlock(&usock->owner->sync);
}

static void sp_data_work_destroy(struct work_struct *work)
{
	struct sp_usock *usock = container_of(work,
		struct sp_usock, work_destroy);

	/*  No need to lock as usock_destroy does this */
	sp_usock_destroy(usock, 0);
}

/*
 * sp_register_usock: register new underlying socket with SP socket
 */
static void sp_register_usock (struct sp_sock *owner, struct sp_usock *usock,
	struct list_head *list, void (*infunc)(struct work_struct*),
	void (*outfunc)(struct work_struct*),
	void (*statefunc)(struct work_struct*), int active)
{
	/* Basic initialisation */
	sp_decoder_init(&usock->decoder, sp_usock_read);
	sp_encoder_init(&usock->encoder, sp_usock_write);

	/* Initialize work items for this socket */
	INIT_WORK(&usock->work_in, infunc);
	INIT_WORK(&usock->work_out, outfunc);
	INIT_WORK(&usock->work_destroy, statefunc);

	/* Install callbacks for work items */
	write_lock_bh(&usock->s->sk->sk_callback_lock);
	usock->active = active;
	usock->s->sk->sk_user_data = (void *)usock;
	usock->old_sk_state_change = usock->s->sk->sk_state_change;
	usock->old_sk_data_ready = usock->s->sk->sk_data_ready;
	usock->old_sk_write_space = usock->s->sk->sk_write_space;
	if (infunc)
		usock->s->sk->sk_data_ready = sp_in_cb;
	if (outfunc)
		usock->s->sk->sk_write_space = sp_out_cb;
	if (statefunc)
		usock->s->sk->sk_state_change = sp_state_cb;
	write_unlock_bh(&usock->s->sk->sk_callback_lock);

	/* Add the new socket to the list of underlying sockets */
        usock->owner = owner;
	mutex_lock (&owner->sync);
	list_add(&usock->list, list);
	mutex_unlock (&owner->sync);

	printk (KERN_INFO "SP: %s owner=%p sk=%p\n", __func__, usock->owner,
		usock->s->sk);
}

/*
 * sp_listener_work_in: Work handler to accept a new connection
 */
static void sp_listener_work_in(struct work_struct *work)
{
	struct sp_usock *listener = container_of(work,
		struct sp_usock, work_in);
	struct socket *new_sock;
	struct sp_usock *new_usock;
	int rc;

	for(;;) {

		/* Accept the new connection */
		rc = kernel_accept(listener->s, &new_sock, O_NONBLOCK);
		if (rc == -EAGAIN)
			break;
		if (rc < 0) {
			printk(KERN_INFO "SP: %s: accept returned %d\n",
				__func__, -rc);
			return;
		}

		/* Allocate and initialise the underlying socket */
		new_usock = kmalloc(sizeof (struct sp_usock), GFP_KERNEL);
		BUG_ON (!new_usock);
		new_usock->s = new_sock;

		/* Register the TCP socket with the SP socket */
		printk(KERN_INFO "SP: %s registering accepted peer sk=%p\n",
			__func__, new_usock->s->sk);
		sp_register_usock (listener->owner, new_usock,
			&listener->owner->connections,
			sp_data_work_in, sp_data_work_out,
			sp_data_work_destroy, 1);
	}
}

/*
 * sp_in_cb: A callback from underlying socket
 *
 * It executes the work associated with in incoming data.
 */
static void sp_in_cb(struct sock *sk, int bytes)
{
	struct sp_usock *usock = (struct sp_usock *)(sk->sk_user_data);

	printk(KERN_INFO "SP: in_cb owner=%p sk=%p bytes=%d\n", usock->owner,
		sk, (int) bytes);

	/* Add the work to global workqueue, if not already there */
	schedule_work(&usock->work_in);
}

/*
 * sp_out_cb: A callback from underlying socket
 *
 * It executes the work associated with in outgoing data.
 */
static void sp_out_cb(struct sock *sk)
{
	struct sp_usock *usock = (struct sp_usock *)(sk->sk_user_data);

	printk(KERN_INFO "SP: out_cb owner=%p sk=%p\n", usock->owner, sk);

	/* Add the work to global workqueue, if not already there */
	schedule_work(&usock->work_out);
}

/*
 * sp_state_cb: A callback from underlying socket
 *
 * Called when an underlying socket changes TCP state.
 * Currently only used to destroy the underlying socket in the event
 * of a passive close (TCP_CLOSE_WAIT).
 *
 */
static void sp_state_cb(struct sock *sk)
{
	struct sp_usock *usock = (struct sp_usock *)(sk->sk_user_data);

	printk(KERN_INFO "SP: state_cb owner=%p sk=%p sk_state=%d\n",
		usock->owner, sk, sk->sk_state);

	write_lock_bh(sk->sk_callback_lock);
	/* kernel_connect() has completed on this socket */
	if (sk->sk_state == TCP_ESTABLISHED)
		usock->active = 1;
	/* Remote peer has closed the connection, schedule work item to
	   deregister the underlying socket */
	else if (sk->sk_state == TCP_CLOSE_WAIT)
		schedule_work(&usock->work_destroy);
	write_unlock_bh(sk->sk_callback_lock);
}

/*
 * sp_sendmsg: Send a message to a socket
 */
static int sp_sendmsg(struct kiocb *kiocb, struct socket *sock,
	struct msghdr *msg, size_t len)
{
	struct sp_usock *usock;
	int rc = 0;
	struct sp_sock *sp = container_of (sock->sk, struct sp_sock, sk);

	mutex_lock(&sp->sync);

loop:
	list_for_each_entry(usock, &sp->connections, list) {

		/* Skip inactive peers */
		read_lock_bh(&usock->s->sk->sk_callback_lock);
		if (!usock->active) {
			read_unlock_bh(&usock->s->sk->sk_callback_lock);
			continue;
		}
		read_unlock_bh(&usock->s->sk->sk_callback_lock);

		/* Try to put the message to the specific underlying socket */
		rc = sp_encoder_put_message(&usock->encoder, msg, len);
		if (rc != -EAGAIN) {

			/* Forward the error to the caller */
			if (rc < 0)
				goto out_unlock;

			/* Message successfully sent */
			rc = len;
			goto out_unlock;
		}
	}

	/* Nowhere to send the message and we are in the non-blocking mode */
	if (msg->msg_flags & MSG_DONTWAIT) {
		rc = -EAGAIN;
		goto out_unlock;
	}

	/* Wait till we can send */
	if (sp->send_waiting != 1) {
		sp->send_waiting = 1;
		init_completion(&sp->send_wait);
	}
	mutex_unlock(&sp->sync);
	rc = wait_for_completion_interruptible(&sp->send_wait);
	if (rc < 0)
		goto out_unlock;
	mutex_lock(&sp->sync);
	goto loop;

out_unlock:
	mutex_unlock(&sp->sync);
	return rc;
}

/*
 * sp_recvmsg: Receive a message from a socket
 */
static int sp_recvmsg(struct kiocb *iocb, struct socket *sock,
	struct msghdr *msg, size_t size, int flags)
{
	struct sp_sock *sp = container_of (sock->sk, struct sp_sock, sk);
	struct sp_usock *usock;
	int rc;
	void *msg_data;
	int msg_size;

	mutex_lock(&sp->sync);

loop:
	/* Loop over all the underlying sockets */
	list_for_each_entry(usock, &sp->connections, list) {

		/* Skip inactive peers */
		read_lock_bh(&usock->s->sk->sk_callback_lock);
		if (!usock->active) {
			read_unlock_bh(&usock->s->sk->sk_callback_lock);
			continue;
		}
		read_unlock_bh(&usock->s->sk->sk_callback_lock);

		/*  Try to get a message from this underlying socket */
		rc = sp_decoder_get_message(&usock->decoder, size,
			&msg_data, &msg_size);

		/* If there is a message, copy it to the supplied buffer */
		if (rc == 0) {
			rc = memcpy_toiovec(msg->msg_iov, msg_data, msg_size);
			if (rc < 0)
				goto out_unlock;
			rc = msg_size;
			goto out_unlock;
		}

		/*  Forward the error up the stack */
		if (rc != -EAGAIN)
			goto out_unlock;
	}

	/* There are no message and we are in the non-blocking mode */
	if (flags & MSG_DONTWAIT) {
		rc = -EAGAIN;
		goto out_unlock;
	}

	/* Wait till message arrives (unlock the socket mutex meanwhile) */
	if (sp->recv_waiting != 1) {
		sp->recv_waiting = 1;
		init_completion(&sp->recv_wait);
	}
	mutex_unlock(&sp->sync);
	rc = wait_for_completion_interruptible(&sp->recv_wait);
	if (rc < 0)
		goto out_unlock;
	mutex_lock(&sp->sync);
	goto loop;

out_unlock:
	mutex_unlock(&sp->sync);
	return rc;
}

/*
 * sp_bind: Bind SP socket to an endpoint 
 */
static int sp_bind(struct socket *sock, struct sockaddr *addr,
	int addr_len)
{
	struct sock *sk = sock->sk;
	struct sp_sock *sp = (struct sp_sock *)sk;
	struct sockaddr_sp *addr_sp;
	struct sp_usock *usock;
	int protocol;
	struct sockaddr_storage uaddr;
	int uaddr_len;
	int rc;

	/* Cast the address to proper SP address */
	if (addr->sa_family != AF_SP) {
		rc = -EAFNOSUPPORT;
		goto out;
	}
	addr_sp = (struct sockaddr_sp *)addr;

	printk(KERN_INFO "SP: Binding to %s", addr_sp->ssp_endpoint);

	/* Convert the textual address into a structure */
	rc = sp_parse_address (addr_sp->ssp_endpoint, &protocol,
		&uaddr, &uaddr_len);
	if (rc < 0)
		goto out;

	/* Allocate and initialise the underlying socket */
	usock = kmalloc(sizeof (struct sp_usock), GFP_KERNEL);
	if (!usock) {
		rc = -ENOMEM;
		goto out;
	}

	if (protocol == SP_PROTOCOL_TCP) {
		rc = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP,
			&usock->s);
		if (rc < 0)
			goto out_dealloc;

		/* Register the TCP listener socket with the SP socket */
		printk(KERN_INFO "SP: %s registering listener sk=%p\n",
			__func__, usock->s->sk);
		sp_register_usock (sp, usock, &sp->listeners,
			sp_listener_work_in, NULL, NULL, 1);

		/* Bind and listen for connections on listener socket */
		rc = kernel_bind(usock->s, (struct sockaddr *)&uaddr,
			uaddr_len);
		if (rc < 0)
			goto out_release;

		rc = kernel_listen(usock->s, 1);
		if (rc < 0)
			goto out_release;
	}
	else {
		/* This should not happen. If parsing was successfull */
		/* we should be able to bind */
		BUG();
	}
	
	/* Socket is now bound, connections will be accepted asynchronously */
	rc = 0;
	goto out;

out_release:
	sock_release(usock->s);
	list_del(&usock->list);
out_dealloc:
	kfree(usock);
out:
	return rc;
}

/*
 * sp_connect: Connect SP socket to an endpoint
 */
static int sp_connect(struct socket *sock, struct sockaddr *addr,
	int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct sp_sock *sp = (struct sp_sock *)sk;
	struct sockaddr_sp *addr_sp;
	struct sp_usock *usock;
	int protocol;
	struct sockaddr_storage uaddr;
	int uaddr_len;
	int rc;

	/* Cast the address to proper SP address */
	if (addr->sa_family != AF_SP) {
		rc = -EAFNOSUPPORT;
		goto out;
	}
	addr_sp = (struct sockaddr_sp *)addr;

	printk(KERN_INFO "SP: Connecting to %s\n", addr_sp->ssp_endpoint);

	/* Convert the textual address into a structure */
	rc = sp_parse_address (addr_sp->ssp_endpoint, &protocol,
		&uaddr, &uaddr_len);
	if (rc < 0)
		goto out;

	/* Allocate and initialise the underlying socket */
	usock = kmalloc(sizeof (struct sp_usock), GFP_KERNEL);
	if (!usock) {
		rc = -ENOMEM;
		goto out;
	}

	if (protocol == SP_PROTOCOL_TCP) {
		rc = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP,
			&usock->s);
		if (rc < 0)
			goto out_dealloc;

		/* Register the TCP socket with the SP socket */
		printk(KERN_INFO "SP: %s: registering connected peer sk=%p\n",
			__func__, usock->s->sk);
		sp_register_usock (sp, usock, &sp->connections,
			sp_data_work_in, sp_data_work_out,
			sp_data_work_destroy, 0);

		/* Start connecting to the peer */
		rc = kernel_connect(usock->s, (struct sockaddr *)&uaddr,
			uaddr_len, O_NONBLOCK);
		if (rc < 0 && rc != -EINPROGRESS)
			goto out_release;
		/* Success will be reported by sp_state_cb setting usock->active
		   to 1; TODO handle failures/reconnect */
	}
	else {
		/* This should not happen. If parsing was successfull */
		/* we should be able to bind */
		BUG();
	}
	
	/* Socket is now bound, connections will be accepted asynchronously */
	rc = 0;
	goto out;

out_release:
	sock_release(usock->s);
	list_del(&usock->list);
out_dealloc:
	kfree(usock);
out:
	return rc;
}

/*
 * sp_release: Close an SP socket
 */
static int sp_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct sp_sock *sp = (struct sp_sock *)sk;
	struct sp_usock *it, *next;

	if (!sk)
		return 0;

	/* First, destroy all the underlying listeners */
	list_for_each_entry_safe(it, next, &sp->listeners, list) {
		sp_usock_destroy (it, 1);
		printk(KERN_INFO "SP: Underlying listener deallocated\n");
	}

	/* First, destroy all the underlying connections */
	list_for_each_entry_safe(it, next, &sp->connections, list) {
		sp_usock_destroy (it, 1);
	}

	/* Detach socket from process context. */
	sock_hold(sk);
	sock_orphan(sk);
	sock_put(sk);

	printk(KERN_INFO "SP: %s destroyed SP socket sk=%p\n", __func__,
		sock->sk);
	sock->sk = NULL;

	return 0;
}

/*
 * sp_destruct: SP socket destructor
 *
 * Called when an SP socket is freed.
 */
static void sp_destruct(struct sock *sk)
{
	/* Decrement protocol family refcount */
	local_bh_disable();
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	local_bh_enable();
}

/*
 * sp_create: Create an unconnected SP socket
 */
static int sp_create(struct net *net, struct socket *sock, int protocol,
	int kern)
{
	struct sock *sk;
	struct sp_sock *sp;

	if (protocol && protocol != PF_SP)
		return -EPROTONOSUPPORT;

	/* Set up the table of virtual functions for the socket */
	sock->ops = &sp_sock_ops;

	/* Allocate private data */
	sk = sk_alloc(net, PF_SP, GFP_KERNEL, &sp_proto);
	if (!sk)
		return -ENOMEM;

	/* Initialise the underlying socket */
	sock_init_data(sock, sk);
	sk->sk_destruct	= sp_destruct;

	/* Initialise the SP socket itself */
	sp = (struct sp_sock *)sk;
	INIT_LIST_HEAD(&sp->listeners);
	INIT_LIST_HEAD(&sp->connections);
	mutex_init(&sp->sync);
	sp->recv_waiting = 0;
	sp->send_waiting = 0;

	/* Increment procotol family refcount */
	local_bh_disable();
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	local_bh_enable();

	printk(KERN_INFO "SP: %s created SP socket sk=%p\n", __func__, sp);

	return 0;
}

/*
 * af_sp_init: Intialise SP protocol family
 */
static int __init af_sp_init(void)
{
	int rc;

	rc = proto_register(&sp_proto, 1);
	if (rc != 0) {
		printk(KERN_CRIT "%s: Cannot create sp_sock SLAB cache!\n",
			__func__);
		goto out;
	}

	sock_register(&sp_family_ops);
out:
	return rc;
}

/*
 * af_sp_exit: Uninitialise SP procotol family
 */
static void __exit af_sp_exit(void)
{
	sock_unregister(PF_SP);
	proto_unregister(&sp_proto);
}

fs_initcall(af_sp_init);
module_exit(af_sp_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS_NETPROTO(PF_SP);
