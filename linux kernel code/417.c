struct user_msghdr {
	void		__user *msg_name;	/* ptr to socket address structure */
	int		msg_namelen;		/* size of socket address structure */
	struct iovec	__user *msg_iov;	/* scatter/gather array */
	__kernel_size_t	msg_iovlen;		/* # elements in msg_iov  msg_iov数组元素的个数*/
	void		__user *msg_control;	/* ancillary data */
	__kernel_size_t	msg_controllen;		/* ancillary data buffer length */
	unsigned int	msg_flags;		/* flags on received message */
};

/* For recvmmsg/sendmmsg */
struct mmsghdr {
	struct user_msghdr  msg_hdr;
	unsigned int        msg_len;
};

struct msghdr {
	void		*msg_name;	/* ptr to socket address structure */
	int		msg_namelen;	/* size of socket address structure */
	struct iov_iter	msg_iter;	/* data */
	void		*msg_control;	/* ancillary data */
	__kernel_size_t	msg_controllen;	/* ancillary data buffer length */
	unsigned int	msg_flags;	/* flags on received message */
	struct kiocb	*msg_iocb;	/* ptr to iocb for async requests */
};


/**
 *  struct socket - general BSD socket
 *  @state: socket state (%SS_CONNECTED, etc)
 *  @type: socket type (%SOCK_STREAM, etc)
 *  @flags: socket flags (%SOCK_NOSPACE, etc)
 *  @ops: protocol specific socket operations
 *  @file: File back pointer for gc
 *  @sk: internal networking protocol agnostic socket representation
 *  @wq: wait queue for several uses
 */
struct socket {
	socket_state		state;

	short			type;

	unsigned long		flags;

	struct socket_wq	*wq;

	struct file		*file;
	struct sock		*sk;
	const struct proto_ops	*ops;
};

struct iovec
{
	void __user *iov_base;	/* BSD uses caddr_t (1003.1g requires void *) 开始地址*/
	__kernel_size_t iov_len; /* Must be size_t (1003.1g) 长度*/
};

#define MSG_ERRQUEUE	0x2000	/* Fetch message from error queue */

#if defined(CONFIG_COMPAT)
#define MSG_CMSG_COMPAT	0x80000000	/* This message needs 32 bit fixups */
#else
#define MSG_CMSG_COMPAT	0		/* We never have 32 bit fixups */
#endif

SYSCALL_DEFINE5(recvmmsg, int, fd, struct mmsghdr __user *, mmsg,
		unsigned int, vlen, unsigned int, flags,
		struct __kernel_timespec __user *, timeout)
{
	if (flags & MSG_CMSG_COMPAT)
		return -EINVAL;

	return __sys_recvmmsg(fd, mmsg, vlen, flags, timeout, NULL);
}

int __sys_recvmmsg(int fd, struct mmsghdr __user *mmsg,
		   unsigned int vlen, unsigned int flags,
		   struct __kernel_timespec __user *timeout,
		   struct old_timespec32 __user *timeout32)
{
	int datagrams;
	struct timespec64 timeout_sys;

	if (timeout && get_timespec64(&timeout_sys, timeout))   //转换类型
		return -EFAULT;

	if (timeout32 && get_old_timespec32(&timeout_sys, timeout32))   //在此为NULL
		return -EFAULT;

	if (!timeout && !timeout32) //两个都为NULL
		return do_recvmmsg(fd, mmsg, vlen, flags, NULL);    //无限阻塞直到vlen

	datagrams = do_recvmmsg(fd, mmsg, vlen, flags, &timeout_sys);

	if (datagrams <= 0)
		return datagrams;

	if (timeout && put_timespec64(&timeout_sys, timeout))   //应该是剩余时间？
		datagrams = -EFAULT;

	if (timeout32 && put_old_timespec32(&timeout_sys, timeout32))
		datagrams = -EFAULT;

	return datagrams;
}

static int do_recvmmsg(int fd, struct mmsghdr __user *mmsg,
			  unsigned int vlen, unsigned int flags,
			  struct timespec64 *timeout)
{
	int fput_needed, err, datagrams;
	struct socket *sock;
	struct mmsghdr __user *entry;
	struct compat_mmsghdr __user *compat_entry;
	struct msghdr msg_sys;
	struct timespec64 end_time;
	struct timespec64 timeout64;

	if (timeout &&
	    poll_select_set_timeout(&end_time, timeout->tv_sec,
				    timeout->tv_nsec))	//timeout到to指针（end_time） to=后两个参数加上当前的mon单调时间；
		return -EINVAL;					//如果后两个参数为0，to也为0

	datagrams = 0;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);	//获取fd对应的socket
	if (!sock)
		return err;

	if (likely(!(flags & MSG_ERRQUEUE))) {
		err = sock_error(sock->sk);
		if (err) {
			datagrams = err;
			goto out_put;
		}
	}

	entry = mmsg;	//存放消息的参数指针
	compat_entry = (struct compat_mmsghdr __user *)mmsg;

	while (datagrams < vlen) {		//循环接收消息，直到vlen个或者时间超时
		/*
		 * No need to ask LSM for more than the first datagram.
		 */
		if (MSG_CMSG_COMPAT & flags) {
			err = ___sys_recvmsg(sock, (struct user_msghdr __user *)compat_entry,	//compat_entry也是返回值，保存数据
					     &msg_sys, flags & ~MSG_WAITFORONE,
					     datagrams);	//msg_sys 返回值
			if (err < 0)
				break;
			err = __put_user(err, &compat_entry->msg_len);
			++compat_entry;
		} else {
			err = ___sys_recvmsg(sock,
					     (struct user_msghdr __user *)entry,
					     &msg_sys, flags & ~MSG_WAITFORONE,
					     datagrams);
			if (err < 0)
				break;
			err = put_user(err, &entry->msg_len);
			++entry;
		}

		if (err)
			break;
		++datagrams;

		/* MSG_WAITFORONE turns on MSG_DONTWAIT after one packet */
		if (flags & MSG_WAITFORONE)
			flags |= MSG_DONTWAIT;

		if (timeout) {
			ktime_get_ts64(&timeout64);
			*timeout = timespec64_sub(end_time, timeout64);
			if (timeout->tv_sec < 0) {
				timeout->tv_sec = timeout->tv_nsec = 0;
				break;
			}

			/* Timeout, return less than vlen datagrams */
			if (timeout->tv_nsec == 0 && timeout->tv_sec == 0)
				break;
		}

		/* Out of band data, return right away */
		if (msg_sys.msg_flags & MSG_OOB)
			break;
		cond_resched();
	}

	if (err == 0)
		goto out_put;

	if (datagrams == 0) {
		datagrams = err;
		goto out_put;
	}

	/*
	 * We may return less entries than requested (vlen) if the
	 * sock is non block and there aren't enough datagrams...
	 */
	if (err != -EAGAIN) {
		/*
		 * ... or  if recvmsg returns an error after we
		 * received some datagrams, where we record the
		 * error to return on the next call or if the
		 * app asks about it using getsockopt(SO_ERROR).
		 */
		sock->sk->sk_err = -err;
	}
out_put:
	fput_light(sock->file, fput_needed);

	return datagrams;
}


static int ___sys_recvmsg(struct socket *sock, struct user_msghdr __user *msg,
			 struct msghdr *msg_sys, unsigned int flags, int nosec)
{
	struct compat_msghdr __user *msg_compat =
	    (struct compat_msghdr __user *)msg;
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	unsigned long cmsg_ptr;
	int len;
	ssize_t err;

	/* kernel mode address */
	struct sockaddr_storage addr;	

	/* user mode address pointers */
	struct sockaddr __user *uaddr;
	int __user *uaddr_len = COMPAT_NAMELEN(msg);	//长度

	msg_sys->msg_name = &addr;	//socket地址

	if (MSG_CMSG_COMPAT & flags)
		err = get_compat_msghdr(msg_sys, msg_compat, &uaddr, &iov);
	else
		err = copy_msghdr_from_user(msg_sys, msg, &uaddr, &iov); //msg拷贝到msg_sys ?? uaddr保存msg的msg_name
	if (err < 0)
		return err;

	cmsg_ptr = (unsigned long)msg_sys->msg_control;
	msg_sys->msg_flags = flags & (MSG_CMSG_CLOEXEC|MSG_CMSG_COMPAT);

	/* We assume all kernel code knows the size of sockaddr_storage */
	msg_sys->msg_namelen = 0;

	if (sock->file->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	err = (nosec ? sock_recvmsg_nosec : sock_recvmsg)(sock, msg_sys, flags);	//接收消息
	if (err < 0)
		goto out_freeiov;
	len = err;

	if (uaddr != NULL) {
		err = move_addr_to_user(&addr,
					msg_sys->msg_namelen, uaddr,
					uaddr_len);
		if (err < 0)
			goto out_freeiov;
	}
	err = __put_user((msg_sys->msg_flags & ~MSG_CMSG_COMPAT),
			 COMPAT_FLAGS(msg));
	if (err)
		goto out_freeiov;
	if (MSG_CMSG_COMPAT & flags)
		err = __put_user((unsigned long)msg_sys->msg_control - cmsg_ptr,
				 &msg_compat->msg_controllen);
	else
		err = __put_user((unsigned long)msg_sys->msg_control - cmsg_ptr,
				 &msg->msg_controllen);
	if (err)
		goto out_freeiov;
	err = len;

out_freeiov:
	kfree(iov);
	return err;
}
