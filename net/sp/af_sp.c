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

static const struct proto_ops sp_ops = {
        .family =	PF_SP,
	.owner =	THIS_MODULE,
	.release =	sp_release,
	.bind =		sock_no_bind,
	.connect =	sock_no_connect,
	.socketpair =	sock_no_socketpair,
	.accept =	sock_no_accept,
	.getname =	sock_no_getname,
	.poll =		sock_no_poll,
	.ioctl =	sock_no_ioctl,
	.listen =	sock_no_listen,
	.shutdown =	sock_no_shutdown,
	.setsockopt =	sock_no_setsockopt,
	.getsockopt =	sock_no_getsockopt,
	.sendmsg =	sock_no_sendmsg,
	.recvmsg =	sock_no_recvmsg,
	.mmap =		sock_no_mmap,
	.sendpage =	sock_no_sendpage,
};

static struct proto sp_proto = {
	.name =		"SP",
	.owner =	THIS_MODULE,
	.obj_size =	sizeof(struct sp_sock),
};

static int sp_release(struct socket *sock)
{
	return 0;
}

static int sp_create(struct net *net, struct socket *sock, int protocol,
                     int kern)
{
	sock->ops = &sp_ops;

	return -ESOCKTNOSUPPORT;
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
