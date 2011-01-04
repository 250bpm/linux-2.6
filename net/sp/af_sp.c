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
 * sp_uscok_destroy: clean up the underlying socket
 */
static void sp_usock_destroy (struct sp_usock *usock)
{
	struct sp_sock *owner = usock->owner;
	mutex_lock(&owner->sync);
	sock_release(usock->s);
	list_del(&usock->list);
	if (usock->inmsg_data)
		kfree (usock->inmsg_data);
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
	struct kvec vec;
	struct msghdr hdr;
	unsigned char size;
	int nbytes;

	mutex_lock(&usock->owner->sync);

	/*  If there's no message, read the size and allocate the buffer */
	if (usock->inmsg_data == NULL) {
		memset (&hdr, 0, sizeof hdr);
		vec.iov_base = &size;
		vec.iov_len = 1;
		nbytes = kernel_recvmsg(usock->s, &hdr, &vec, 1, 1,
			MSG_DONTWAIT);
		if (nbytes == 0)
			return;
		BUG_ON (nbytes != 1);

		usock->inmsg_data = kmalloc(size, GFP_KERNEL);
	        BUG_ON (!usock->inmsg_data);
		usock->inmsg_size = size;
		usock->inmsg_pos = 0;
		printk(KERN_INFO "SP: Size %d received", (int) size);
        }

	/*  If the message is fully read there's nothing more to do */
	if (usock->inmsg_pos == usock->inmsg_size)
		goto out;

	/* Try to read the remaining part of the message */
	memset (&hdr, 0, sizeof hdr);
	vec.iov_base = (char *)usock->inmsg_data + usock->inmsg_pos;
	vec.iov_len = usock->inmsg_size - usock->inmsg_pos;
	nbytes = kernel_recvmsg(usock->s, &hdr, &vec, 1, vec.iov_len,
		MSG_DONTWAIT);
	BUG_ON(nbytes < 0);
	usock->inmsg_pos += nbytes;
	if (usock->inmsg_pos == usock->inmsg_size) {
		printk(KERN_INFO "SP: Message fully read (%d bytes)",
			(int)usock->inmsg_size);
		if(usock->owner->recv_waiting) {
			usock->owner->recv_waiting = 0;
			complete(&usock->owner->recv_wait);
		}
	}

out:
	mutex_unlock(&usock->owner->sync);
}

static void sp_data_work_out(struct work_struct *work)
{
	struct sp_usock *usock = container_of(work,
		struct sp_usock, work_out);
	struct kvec vec;
	struct msghdr hdr;
	int nbytes;

	mutex_lock(&usock->owner->sync);

	/* Try to send the remaining part of the message */
	memset (&hdr, 0, sizeof hdr);
	vec.iov_base = (char *)usock->outmsg_data + usock->outmsg_pos;
	vec.iov_len = usock->outmsg_size - usock->outmsg_pos;
	nbytes = kernel_sendmsg(usock->s, &hdr, &vec, 1, vec.iov_len);
	BUG_ON(nbytes < 0);
	usock->outmsg_pos += nbytes;

	/*  If the message is fully sent, clean the buffer */
	if (usock->outmsg_data && usock->outmsg_pos == usock->outmsg_size) {
		kfree(usock->outmsg_data);
		usock->outmsg_data = NULL;
		usock->outmsg_size = 0;
		usock->outmsg_pos = 0;

		if(usock->owner->send_waiting) {
			usock->owner->send_waiting = 0;
			complete(&usock->owner->send_wait);
		}
	}

	mutex_unlock(&usock->owner->sync);
}

/*
 * sp_register_usock: register new underlying socket with SP socket
 */
static void sp_register_usock (struct sp_sock *owner, struct sp_usock *usock,
	struct list_head *list, void (*infunc)(struct work_struct*),
	void (*outfunc)(struct work_struct*))
{
	/* Basic initialisation */
	usock->inmsg_data = NULL;
	usock->inmsg_size = 0;
	usock->inmsg_pos = 0;
	usock->outmsg_data = NULL;
	usock->outmsg_size = 0;
	usock->outmsg_pos = 0;

	/* Install callback to be called when a new connection arrives */
	usock->s->sk->sk_user_data = (void *)usock;
	INIT_WORK(&usock->work_in, infunc);
	INIT_WORK(&usock->work_out, outfunc);
	if (infunc)
		usock->s->sk->sk_data_ready = sp_in_cb;
	if (outfunc)
		usock->s->sk->sk_write_space = sp_out_cb;

	/* Add the new socket to the list of underlying sockets */
        usock->owner = owner;
	mutex_lock (&owner->sync);
	list_add(&usock->list, list);
	mutex_unlock (&owner->sync);

	/* It may be possible to read or write to the socket */
	sp_in_cb (usock->s->sk, 0);
	sp_out_cb (usock->s->sk);
}

/*
 * sp_liatener_work_in: Work handler to accept a new connection
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
		rc = kernel_accept(listener->s, &new_sock, 0);
		if (rc == -EAGAIN)
	      		break;
		if (rc < 0) {
			printk(KERN_INFO "%s: accept returned %d\n",
				__func__, -rc);
			return;
		}


		/* Allocate and initialise the underlying socket */
		new_usock = kmalloc(sizeof (struct sp_usock), GFP_KERNEL);
	        BUG_ON (!new_usock);
		new_usock->s = new_sock;

		/* Register the TCP socket with the SP socket */
	        sp_register_usock (listener->owner, new_usock,
			&listener->owner->connections,
			sp_data_work_in, sp_data_work_out);

		printk(KERN_INFO "SP: New underlying socket accepted");
	}
}

/*
 * sp_in_cb: A callback from underlying socket
 *
 * It executes the work associated with in incoming data.
 */
static void sp_in_cb(struct sock *sk, int bytes)
{
        /* Add the work to global workqueue, if not already there */
        struct sp_usock *usock = (struct sp_usock *)(sk->sk_user_data);
	schedule_work(&usock->work_in);

	printk(KERN_INFO "SP: in_cb bytes=%d", (int) bytes);
}

/*
 * sp_out_cb: A callback from underlying socket
 *
 * It executes the work associated with in outgoing data.
 */
static void sp_out_cb(struct sock *sk)
{
        /* Add the work to global workqueue, if not already there */
        struct sp_usock *usock = (struct sp_usock *)(sk->sk_user_data);
	schedule_work(&usock->work_out);
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

printk(KERN_INFO "SP: send flags=%d", (int) msg->msg_flags);

	/* At the moment, the size is stored as a single byte */
	if (len > 0xff)
		return -EMSGSIZE;

	mutex_lock(&sp->sync);

loop:
	list_for_each_entry(usock, &sp->connections, list) {
		if(!usock->outmsg_data) {

			usock->outmsg_data = kmalloc(len + 1, GFP_KERNEL);
			if (!usock->outmsg_data) {
				rc = -ENOMEM;
				goto out_unlock;
			}
			*((unsigned char*)usock->outmsg_data) = len;
			rc = memcpy_fromiovec((char *)usock->outmsg_data + 1,
				msg->msg_iov, len);
			if (rc < 0)
				goto out_unlock;
			usock->outmsg_size = len;
			usock->outmsg_pos = 0;

			/* Start sending the message */
			sp_out_cb(usock->s->sk);

			/* All the bytes are sent */
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
	struct sp_usock *usock;
	int rc = 0;
	struct sp_sock *sp = container_of (sock->sk, struct sp_sock, sk);

	mutex_lock(&sp->sync);

loop:
	list_for_each_entry(usock, &sp->connections, list) {
		if(usock->inmsg_data && usock->inmsg_pos == usock->inmsg_size) {

			/* Check whether messsage fits into supplied buffer */
			if (size < usock->inmsg_size) {
				rc = -EMSGSIZE;
				goto out_unlock;
			}

			/* Copy the message data to supplied buffer */
			rc = memcpy_toiovec(msg->msg_iov, usock->inmsg_data,
				usock->inmsg_size);
			if (rc < 0)
				goto out_unlock;

			/* Return number of bytes read */
			rc = usock->inmsg_size;

			kfree(usock->inmsg_data);

			usock->inmsg_data = NULL;
			usock->inmsg_size = 0;
			usock->inmsg_pos = 0;

			/* Start reading new message */
			sp_in_cb (usock->s->sk, 0);

			goto out_unlock;
		}
	}

	/* There are no message and we are in the non-blocking mode */
	if (flags & MSG_DONTWAIT) {
		rc = -EAGAIN;
		goto out_unlock;
	}

	/* Wait till message arrives */
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
		sp_register_usock (sp, usock, &sp->listeners,
			sp_listener_work_in, NULL);

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

	printk(KERN_INFO "SP: Connecting to %s", addr_sp->ssp_endpoint);

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
		sp_register_usock (sp, usock, &sp->connections,
			sp_data_work_in, sp_data_work_out);

		/* Start connecting to the peer */
		rc = kernel_connect(usock->s, (struct sockaddr *)&uaddr,
			uaddr_len, O_NONBLOCK);
		if (rc < 0 && rc != -EINPROGRESS)
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
		sp_usock_destroy (it);
		printk(KERN_INFO "SP: Underlying listener deallocated\n");
	}

        /* First, destroy all the underlying connections */
	list_for_each_entry_safe(it, next, &sp->connections, list) {
		sp_usock_destroy (it);
		printk(KERN_INFO "SP: Underlying connection deallocated\n");
	}

        /* Detach socket from process context. */
	sock_hold(sk);
	sock_orphan(sk);
	sock_put(sk);

	sock->sk = NULL;

	printk(KERN_INFO "SP: Socket destroyed");

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

	printk(KERN_INFO "SP: Socket created");

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
