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
#include <linux/sp.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <net/af_sp.h>

static int sp_release(struct socket *);
static int sp_create(struct net *, struct socket *, int, int);
static void sp_sock_destructor(struct sock *);
static int sp_connect(struct socket *, struct sockaddr *, int, int);
static int sp_bind(struct socket *, struct sockaddr *, int);
static int sp_pub_sendmsg(struct kiocb *, struct socket *, struct msghdr *,
	size_t);
static int sp_pub_recvmsg(struct kiocb *, struct socket *, struct msghdr *,
	size_t, int);

/* SP protocol information */
static struct proto sp_proto = {
	.name =		"SP",
	.owner =	THIS_MODULE,
	.obj_size =	sizeof(struct sp_sock),
};

/* SP protocol family operations */
static const struct net_proto_family sp_family_ops = {
	.family =	PF_SP,
	.create =	sp_create,
	.owner =	THIS_MODULE,
};

/* SP SOCK_PUB socket operations */
static const struct proto_ops sp_pub_ops = {
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
	.sendmsg =	sp_pub_sendmsg,
	.recvmsg =	sp_pub_recvmsg,
	.mmap =		sock_no_mmap,
	.sendpage =	sock_no_sendpage,
};

/*
 * sp_sock_destructor: SP socket destructor
 *
 * Called when an SP socket is freed.
 */
static void sp_sock_destructor(struct sock *sk)
{
	struct sp_sock *sp = sp_sk(sk);

	printk(KERN_INFO "%s: Here\n", __func__);

	/* Decrement protocol family refcount */
	local_bh_disable();
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	local_bh_enable();
}

/*
 * sp_release: Close an SP socket
 */
static int sp_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct sp_sock *sp = sp_sk(sk);

	if (!sk)
		return 0;

	sock_hold(sk);

	poll_freewait(&sp->pollset);
	if (sp->peer) {
		sock_release(sp->peer);
		sp->peer = NULL;
	}

	sock_orphan(sk);
	sock_put(sk);

	sock->sk = NULL;

	return 0;
}

/*
 * sp_create: Create an unconnected SP socket
 */
static int sp_create(struct net *net, struct socket *sock, int protocol,
	int kern)
{
	struct sock *sk = NULL;
	struct sp_sock *sp;

	if (protocol && protocol != PF_SP)
		return -EPROTONOSUPPORT;

	switch (sock->type) {
	case SOCK_PUB:
		sock->ops = &sp_pub_ops;
		break;
	default:
		return -ESOCKTNOSUPPORT;
	}

	/* Initial state is not connected */
	sock->state = SS_UNCONNECTED;

	/* Allocate SP private data */
	sk = sk_alloc(net, PF_SP, GFP_KERNEL, &sp_proto);
	if (!sk)
		return -ENOMEM;
	sock_init_data(sock, sk);
	sk->sk_destruct	= sp_sock_destructor;
	sp = sp_sk(sk);
	sp->peer = NULL;
	poll_initwait(&sp->pollset);

	/* Increment procotol family refcount */
	local_bh_disable();
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	local_bh_enable();

	return 0;
}

/*
 * sp_bind: Bind SP socket to an endpoint 
 */
static int sp_bind(struct socket *sock, struct sockaddr *addr,
	int addr_len)
{
	return -EOPNOTSUPP;
}

/*
 * sp_connect: Connect SP socket to an endpoint
 */
static int sp_connect(struct socket *sock, struct sockaddr *addr,
	int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_in *addr_in;
	struct sp_sock *sp = sp_sk(sk);
	int rc;

	/* Only AF_INET addressing is supported for now */
	if (addr->sa_family != AF_INET) {
		rc = -EAFNOSUPPORT;
		goto out;
	}
	addr_in = (struct sockaddr_in *)addr;

	/* Create peer socket and associated file structure */
	rc = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sp->peer);
	if (rc < 0)
		goto out;
	rc = sock_map_anon(sp->peer, "[sp]", 0);
	/* rc = sock_map_fd(sp->peer, O_CLOEXEC); */
	if (rc < 0)
		goto out_release;

	/* Connect peer socket */
	rc = kernel_connect(sp->peer, addr, addr_len, 0);
	if (rc < 0)
		goto out_release;
	
	/* Socket is now connected */
	sock->state = SS_CONNECTED;

	return 0;

out_release:
	sock_release(sp->peer);
	sp->peer = NULL;
out:
	return rc;
}

/*
 * sp_pub_sendmsg: Send a message to a SOCK_PUB socket
 */
static int sp_pub_sendmsg(struct kiocb *kiocb, struct socket *sock,
	struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct sp_sock *sp = sp_sk(sk);
	struct kvec send_vec;
	struct msghdr send_msg;
	int nbytes;

	if (msg->msg_iovlen != 1)
		return -EOPNOTSUPP;

	if (sock->state != SS_CONNECTED)
		return -ENOTCONN;

	send_vec.iov_base = kmalloc (len, GFP_KERNEL);
	if (!send_vec.iov_base)
		return -ENOMEM;
	if (copy_from_user(send_vec.iov_base,
		msg->msg_iov[0].iov_base, len) != 0) {
		kfree(send_vec.iov_base);
		return -EFAULT; /* ? */
	}
	send_vec.iov_len = len;
	send_msg.msg_name = NULL;
	send_msg.msg_namelen = 0;
	send_msg.msg_control = NULL;
	send_msg.msg_controllen = 0;
	send_msg.msg_flags = 0;
	nbytes = kernel_sendmsg(sp->peer, &send_msg, &send_vec, 1, len);
	kfree (send_vec.iov_base);
	return nbytes;
}

/*
 * sp_pub_recvmsg: Receive a message from a SOCK_PUB socket
 */
static int sp_pub_recvmsg(struct kiocb *iocb, struct socket *sock,
			  struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct sp_sock *sp = sp_sk(sk);
	int revents;

	if (sock->state != SS_CONNECTED)
		return -ENOTCONN;

	printk(KERN_INFO "%s: before poll loop \n", __func__);

	while (1) {
		revents = sp->peer->file->f_op->poll(sp->peer->file,
			&sp->pollset.pt);
		if (revents & POLLIN)
			break;
		if (signal_pending(current)) {
			return -EINTR;
		}
		poll_schedule(&sp->pollset, TASK_INTERRUPTIBLE);
		printk(KERN_INFO "%s: in poll loop \n", __func__);
	}

	printk(KERN_INFO "%s: after poll loop \n", __func__);

	return 0;
}

/*
 * af_sp_init: Intialise SP protocol family
 */
static int __init af_sp_init(void)
{
	int rc = -1;

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
