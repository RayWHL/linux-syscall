struct fd {
	struct file *file;
	unsigned int flags;
};

struct timerfd_ctx {
	union {
		struct hrtimer tmr;
		struct alarm alarm;
	} t;
	ktime_t tintv;
	ktime_t moffs;
	wait_queue_head_t wqh;
	u64 ticks;
	int clockid;
	short unsigned expired;
	short unsigned settime_flags;	/* to show in fdinfo */
	struct rcu_head rcu;
	struct list_head clist;
	spinlock_t cancel_lock;
	bool might_cancel;
};

struct file {
	union {
		struct llist_node	fu_llist;
		struct rcu_head 	fu_rcuhead;
	} f_u;
	struct path		f_path;
	struct inode		*f_inode;	/* cached value */
	const struct file_operations	*f_op;  //与文件操作有关的指针，函数

	/*
	 * Protects f_ep_links, f_flags.
	 * Must not be taken from IRQ context.
	 */
	spinlock_t		f_lock;
	enum rw_hint		f_write_hint;
	atomic_long_t		f_count;
	unsigned int 		f_flags;    //文件标志，检测是否是非阻塞操作
	fmode_t			f_mode;  //文件模式 可读可写
	struct mutex		f_pos_lock;
	loff_t			f_pos;  //文件读写位置
	struct fown_struct	f_owner;
	const struct cred	*f_cred;
	struct file_ra_state	f_ra;

	u64			f_version;
#ifdef CONFIG_SECURITY
	void			*f_security;
#endif
	/* needed for tty driver, and maybe others */
	void			*private_data;  //可用于任何目的 这里指向了timerfd_ctx

#ifdef CONFIG_EPOLL
	/* Used by fs/eventpoll.c to link all the hooks to this file */
	struct list_head	f_ep_links;
	struct list_head	f_tfile_llink;
#endif /* #ifdef CONFIG_EPOLL */
	struct address_space	*f_mapping;
	errseq_t		f_wb_err;
} __randomize_layout
  __attribute__((aligned(4)));	/* lest something weird decides that 2 is OK */

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __randomize_layout;

//目录项
struct dentry {
	/* RCU lookup touched fields */
	unsigned int d_flags;		/* protected by d_lock */
	seqcount_t d_seq;		/* per dentry seqlock */
	struct hlist_bl_node d_hash;	/* lookup hash list */
	struct dentry *d_parent;	/*父目录指针 parent directory */
	struct qstr d_name;		//目录或者文件名
	struct inode *d_inode;		/* Where the name belongs to - NULL is 目录的inode结点
					 * negative */
	unsigned char d_iname[DNAME_INLINE_LEN];	/* small names */

	/* Ref lookup also touches following */
	struct lockref d_lockref;	/* per-dentry lock and refcount */
	const struct dentry_operations *d_op;
	struct super_block *d_sb;	/*目录的超级块指针 The root of the dentry tree */
	unsigned long d_time;		/*最近使用时间 used by d_revalidate */
	void *d_fsdata;			/*私有数据 fs-specific data */

	union {
		struct list_head d_lru;		/* LRU list */
		wait_queue_head_t *d_wait;	/* in-lookup ones only */
	};
	struct list_head d_child;	/* child of parent list */
	struct list_head d_subdirs;	/* 目录子项指针 our children */
	/*
	 * d_alias and d_rcu can share memory
	 */
	union {
		struct hlist_node d_alias;	/* inode alias list */
		struct hlist_bl_node d_in_lookup_hash;	/* only for in-lookup ones */
	 	struct rcu_head d_rcu;
	} d_u;
} __randomize_layout;

/*
 * This is the Inode Attributes structure, used for notify_change().  It
 * uses the above definitions as flags, to know which values have changed.
 * Also, in this manner, a Filesystem can look at only the values it cares
 * about.  Basically, these are the attributes that the VFS layer can
 * request to change from the FS layer.
 *
 * Derek Atkins <warlord@MIT.EDU> 94-10-20
 */
struct iattr {
	unsigned int	ia_valid;	//描述以下哪些需要改变
	umode_t		ia_mode;
	kuid_t		ia_uid;
	kgid_t		ia_gid;
	loff_t		ia_size;
	struct timespec64 ia_atime;  //access time
	struct timespec64 ia_mtime;		//modify time
	struct timespec64 ia_ctime;		//create time

	/*
	 * Not an attribute, but an auxiliary info for filesystems wanting to
	 * implement an ftruncate() like method.  NOTE: filesystem should
	 * check for (ia_valid & ATTR_FILE), and not for (ia_file != NULL).
	 */
	struct file	*ia_file;
};

typedef u32 compat_ulong_t;		//unsigned int

/* commonly an fd_set represents 256 FDs */
#define FD_SETSIZE 256
typedef struct { uint32_t fd32[FD_SETSIZE/32]; } fd_set;	//uint32_t = u32

typedef u32 compat_size_t;
typedef u32 compat_uptr_t;

struct thread_info {
	struct pcb_struct	pcb;		/* palcode state */

	struct task_struct	*task;		/* main task structure */
	unsigned int		flags;		/* low level flags */
	unsigned int		ieee_state;	/* see fpu.h */

	mm_segment_t		addr_limit;	/* thread address space */
	unsigned		cpu;		/* current CPU */
	int			preempt_count; /* 0 => preemptable, <0 => BUG */
	unsigned int		status;		/* thread-synchronous flags */

	int bpt_nsaved;
	unsigned long bpt_addr[2];		/* breakpoint handling  */
	unsigned int bpt_insn[2];
};

#define _NSIG		64
#define _NSIG_BPW	64
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

typedef unsigned long old_sigset_t;		/* at least 32 bits */

typedef struct {
	unsigned long sig[_NSIG_WORDS];
} sigset_t;

typedef sigset_t compat_sigset_t;

//pselect6_time64
static long do_compat_pselect(int n, compat_ulong_t __user *inp,
	compat_ulong_t __user *outp, compat_ulong_t __user *exp,
	void __user *tsp, compat_sigset_t __user *sigmask,		//compat_sigset_t  //tsp为相对时间
	compat_size_t sigsetsize, enum poll_time_type type)	//compat_size_t u32
{
	sigset_t ksigmask, sigsaved;	//包含一个long的结构
	struct timespec64 ts, end_time, *to = NULL;
	int ret;

	if (tsp) {
		switch (type) {
		case PT_OLD_TIMESPEC:
			if (get_old_timespec32(&ts, tsp))
				return -EFAULT;
			break;
		case PT_TIMESPEC:
			if (get_timespec64(&ts, tsp))
				return -EFAULT;
			break;
		default:
			BUG();
		}

		to = &end_time;
		if (poll_select_set_timeout(to, ts.tv_sec, ts.tv_nsec))	//tsp到ts，再到to指针（end_time） to=后两个参数加上当前的mon单调时间；如果后两个参数为0，to也为0
			return -EINVAL;
	}

	ret = set_compat_user_sigmask(sigmask, &ksigmask, &sigsaved, sigsetsize);	//1、4参数为输入，2、3参数为输出
	if (ret)																	//将sigmask拷贝到ksigmask ， sigsaved指向current->blocked以保存原值
		return ret;																//设置currnet->blocked为ksigmask 修改进程阻塞信号

	ret = compat_core_sys_select(n, inp, outp, exp, to);	//设置超时时间 没看实现过程
	ret = poll_select_copy_remaining(&end_time, tsp, type, ret);	//获取剩余时间 存入tsp

	restore_user_sigmask(sigmask, &sigsaved);	//保存原信号

	return ret;
}

#define __get_user(x, ptr) \
  __get_user_nocheck((x), (ptr), sizeof(*(ptr)))

#define __get_user_nocheck(x, ptr, size)			\
({								\
	long __gu_err = 0;					\
	unsigned long __gu_val;					\
	__chk_user_ptr(ptr);					\
	switch (size) {						\
	  case 1: __get_user_8(ptr); break;			\
	  case 2: __get_user_16(ptr); break;			\
	  case 4: __get_user_32(ptr); break;			\
	  case 8: __get_user_64(ptr); break;			\
	  default: __get_user_unknown(); break;			\
	}							\
	(x) = (__force __typeof__(*(ptr))) __gu_val;		\
	__gu_err;						\
})



COMPAT_SYSCALL_DEFINE6(pselect6_time64, int, n, compat_ulong_t __user *, inp,
	compat_ulong_t __user *, outp, compat_ulong_t __user *, exp,
	struct __kernel_timespec __user *, tsp, void __user *, sig)
{
	compat_size_t sigsetsize = 0;	//u32
	compat_uptr_t up = 0;		//u32

	if (sig) {
		if (!access_ok(sig,
				sizeof(compat_uptr_t)+sizeof(compat_size_t)) ||
				__get_user(up, (compat_uptr_t __user *)sig) ||
				__get_user(sigsetsize,
				(compat_size_t __user *)(sig+sizeof(up))))
			return -EFAULT;
	}

	return do_compat_pselect(n, inp, outp, exp, tsp, compat_ptr(up),  //up信号sigmask
				 sigsetsize, PT_TIMESPEC);
}

struct pollfd {
	int fd;		//监听的文件描述符
	short events;	//监听事件
	short revents;	//产生事件
};


/* New compat syscall for 64 bit time_t  */
COMPAT_SYSCALL_DEFINE5(ppoll_time64, struct pollfd __user *, ufds,
	unsigned int,  nfds, struct __kernel_timespec __user *, tsp,
	const compat_sigset_t __user *, sigmask, compat_size_t, sigsetsize)		//1： sigset_t结构，包括一个long数组  2：u32
{
	sigset_t ksigmask, sigsaved;
	struct timespec64 ts, end_time, *to = NULL;
	int ret;

	if (tsp) {
		if (get_timespec64(&ts, tsp))
			return -EFAULT;

		to = &end_time;
		if (poll_select_set_timeout(to, ts.tv_sec, ts.tv_nsec))	//tsp到ts，再到to指针（end_time） to=后两个参数加上当前的mon单调时间；如果后两个参数为0，to也为0
			return -EINVAL;
	}

	ret = set_compat_user_sigmask(sigmask, &ksigmask, &sigsaved, sigsetsize); //1、4参数为输入，2、3参数为输出
	if (ret)																	//将sigmask拷贝到ksigmask ， sigsaved指向current->blocked以保存原值
		return ret;																//设置currnet->blocked为ksigmask 修改进程阻塞信号

	ret = do_sys_poll(ufds, nfds, to);

	restore_user_sigmask(sigmask, &sigsaved);	//保存原信号

	/* We can restart this syscall, usually */
	if (ret == -EINTR)
		ret = -ERESTARTNOHAND;

	ret = poll_select_copy_remaining(&end_time, tsp, PT_TIMESPEC, ret);	//获取剩余时间 存入tsp

	return ret;
}

struct poll_list {
	struct poll_list *next;
	int len;
	struct pollfd entries[0];
};

struct poll_wqueues {
	poll_table pt;
	struct poll_table_page *table;
	struct task_struct *polling_task;
	int triggered;
	int error;
	int inline_index;
	struct poll_table_entry inline_entries[N_INLINE_POLL_ENTRIES];
};



static int do_sys_poll(struct pollfd __user *ufds, unsigned int nfds,
		struct timespec64 *end_time)
{
	struct poll_wqueues table;
 	int err = -EFAULT, fdcount, len, size;
	/* Allocate small arguments on the stack to save memory and be
	   faster - use long to make sure the buffer is aligned properly
	   on 64 bit archs to avoid unaligned access */
	long stack_pps[POLL_STACK_ALLOC/sizeof(long)];		//宏定义256
	struct poll_list *const head = (struct poll_list *)stack_pps;
 	struct poll_list *walk = head;
 	unsigned long todo = nfds;

	if (nfds > rlimit(RLIMIT_NOFILE))
		return -EINVAL;

	len = min_t(unsigned int, nfds, N_STACK_PPS);	//计算栈空间能存放多少描述符
	for (;;) {		//for循环用于拷贝所有文件描述符到poll_list中，一个结点为一页大小
		walk->next = NULL;
		walk->len = len;
		if (!len)
			break;

		if (copy_from_user(walk->entries, ufds + nfds-todo,
					sizeof(struct pollfd) * walk->len))
			goto out_fds;

		todo -= walk->len;
		if (!todo)
			break;

		len = min(todo, POLLFD_PER_PAGE);
		size = sizeof(struct poll_list) + sizeof(struct pollfd) * len;
		walk = walk->next = kmalloc(size, GFP_KERNEL);
		if (!walk) {
			err = -ENOMEM;
			goto out_fds;
		}
	}

	poll_initwait(&table);		//初始化table，将pt指向__pollwait
	fdcount = do_poll(head, &table, end_time);
	poll_freewait(&table);

	for (walk = head; walk; walk = walk->next) {	//将revents拷贝到用户空间
		struct pollfd *fds = walk->entries;
		int j;

		for (j = 0; j < walk->len; j++, ufds++)
			if (__put_user(fds[j].revents, &ufds->revents))
				goto out_fds;
  	}

	err = fdcount;
out_fds:
	walk = head->next;
	while (walk) {	//释放分配的内存
		struct poll_list *pos = walk;
		walk = walk->next;
		kfree(pos);
	}

	return err;
}

