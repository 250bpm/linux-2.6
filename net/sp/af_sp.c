/*
 * SP: An implementation of SP sockets.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/sp.h>
#include <net/af_sp.h>

static int sp_release(struct socket *);
static int sp_create(struct net *, struct socket *, int, int);
static void sp_sock_destructor(struct sock *);
static int sp_connect(struct socket *sock, struct sockaddr *addr,
	int addr_len, int flags);
static int sp_pub_sendmsg(struct kiocb *, struct socket *,
	struct msghdr *, size_t);

static const struct proto_ops sp_pub_ops = {
        .family =	PF_SP,
	.owner =	THIS_MODULE,
	.release =	sp_release,
	.bind =		sock_no_bind,
	.connect =      sp_connect,
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
	.recvmsg =	sock_no_recvmsg,
	.mmap =		sock_no_mmap,
	.sendpage =	sock_no_sendpage,
};

static struct proto sp_proto = {
	.name =		"SP",
	.owner =	THIS_MODULE,
	.obj_size =	sizeof(struct sp_sock),
};

static void sp_sock_destructor(struct sock *sk)
{
	/* struct sp_sock *sp = sp_sk(sk); */

	printk(KERN_INFO "%s: Here\n", __func__);

	local_bh_disable();
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	local_bh_enable();
}

static int sp_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	printk(KERN_INFO "%s: Here\n", __func__);

	if (!sk)
		return 0;

	sock->sk = NULL;

	return 0;
}

static int sp_create(struct net *net, struct socket *sock, int protocol,
                     int kern)
{
	struct sock *sk = NULL;
	struct sp_sock *sp;

	if (protocol && protocol != PF_SP)
		return -EPROTONOSUPPORT;

	printk(KERN_INFO "%s: Here\n", __func__);

	switch (sock->type) {
	case SOCK_PUB:
		sock->ops = &sp_pub_ops;
		break;
	default:
		return -ESOCKTNOSUPPORT;
	}

	sock->state = SS_UNCONNECTED;

	sk = sk_alloc(net, PF_SP, GFP_KERNEL, &sp_proto);
	if (!sk)
	    return -ENOMEM;
	sock_init_data(sock, sk);
	/* lockdep_set_class(&sk->sk_receive_queue.lock,
				&af_unix_sk_receive_queue_lock_key);

	sk->sk_write_space	= unix_write_space;
	sk->sk_max_ack_backlog	= net->unx.sysctl_max_dgram_qlen; */
	sk->sk_destruct		= sp_sock_destructor;
	sp        = sp_sk(sk);
	sp->peer  = NULL;

	local_bh_disable();
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	local_bh_enable();
	return 0;
}

static int sp_connect(struct socket *sock, struct sockaddr *addr,
	int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_sp *sp_addr = (struct sockaddr_sp *)addr;
	struct sp_sock *sp = sp_sk(sk);
	int err;
	struct sockaddr_in peer_addr;

	printk(KERN_CRIT "%s: endpoint is %s\n", __func__,
		sp_addr->ssp_endpoint);

	err = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sp->peer);
	if (err < 0) {
		printk(KERN_INFO "%s: cannot create peer socket: %d\n",
			__func__, -err);
		return err;
	}

	peer_addr.sin_family = AF_INET;
	peer_addr.sin_addr.s_addr = htonl(0x7F000001);
	peer_addr.sin_port = htons(3333);
	err = kernel_connect(sp->peer, (struct sockaddr *) &peer_addr,
		sizeof peer_addr, 0);
	if (err < 0) {
		printk(KERN_INFO "%s: cannot connect peer socket: %d\n",
			__func__, -err);
		sock_release(sp->peer);
		return err;
	}

	sock->state = SS_CONNECTED;
	return 0;
}

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

static const struct net_proto_family sp_family_ops = {
	.family =	PF_SP,
	.create =	sp_create,
	.owner =	THIS_MODULE,
};

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

static void __exit af_sp_exit(void)
{
	sock_unregister(PF_SP);
	proto_unregister(&sp_proto);
}

fs_initcall(af_sp_init);
module_exit(af_sp_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS_NETPROTO(PF_SP);
