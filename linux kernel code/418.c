typedef __kernel_mqd_t		mqd_t;
typedef int __kernel_mqd_t;

#define DEFINE_WAKE_Q(name)				\
	struct wake_q_head name = { WAKE_Q_TAIL, &name.first }

struct wake_q_head {
	struct wake_q_node *first;
	struct wake_q_node **lastp;
};

/* one msg_msg structure for each message */
struct msg_msg {
	struct list_head m_list;
	long m_type;
	size_t m_ts;		/* message text size */
	struct msg_msgseg *next;
	void *security;
	/* the actual message follows immediately */
};


struct audit_context {
	int		    dummy;	/* must be the first element */
	int		    in_syscall;	/* 1 if task is in a syscall */
	enum audit_state    state, current_state;
	unsigned int	    serial;     /* serial number for record */
	int		    major;      /* syscall number */
	struct timespec64   ctime;      /* time of syscall entry */
	unsigned long	    argv[4];    /* syscall arguments */
	long		    return_code;/* syscall return code */
	u64		    prio;
	int		    return_valid; /* return code is valid */
	/*
	 * The names_list is the list of all audit_names collected during this
	 * syscall.  The first AUDIT_NAMES entries in the names_list will
	 * actually be from the preallocated_names array for performance
	 * reasons.  Except during allocation they should never be referenced
	 * through the preallocated_names array and should only be found/used
	 * by running the names_list.
	 */
	struct audit_names  preallocated_names[AUDIT_NAMES];
	int		    name_count; /* total records in names_list */
	struct list_head    names_list;	/* struct audit_names->list anchor */
	char		    *filterkey;	/* key for rule that triggered record */
	struct path	    pwd;
	struct audit_aux_data *aux;
	struct audit_aux_data *aux_pids;
	struct sockaddr_storage *sockaddr;
	size_t sockaddr_len;
				/* Save things to print about task_struct */
	pid_t		    pid, ppid;
	kuid_t		    uid, euid, suid, fsuid;
	kgid_t		    gid, egid, sgid, fsgid;
	unsigned long	    personality;
	……
	union 
	{
		struct {
			mqd_t			mqdes;
			size_t			msg_len;
			unsigned int		msg_prio;
			struct timespec64	abs_timeout;
		} mq_sendrecv;
		...
	};
	
}

struct mqueue_inode_info {		//每个消息队列对应一个该结构
	spinlock_t lock;
	struct inode vfs_inode;
	wait_queue_head_t wait_q;

	struct rb_root msg_tree;
	struct posix_msg_tree_node *node_cache;
	struct mq_attr attr;

	struct sigevent notify;
	struct pid *notify_owner;
	struct user_namespace *notify_user_ns;
	struct user_struct *user;	/* user who created, for accounting */
	struct sock *notify_sock;
	struct sk_buff *notify_cookie;

	/* for tasks waiting for free space and messages, respectively */
	struct ext_wait_queue e_wait_q[2];

	unsigned long qsize; /* size of queue in memory (sum of all msgs) */
};

SYSCALL_DEFINE5(mq_timedsend, mqd_t, mqdes, const char __user *, u_msg_ptr,
		size_t, msg_len, unsigned int, msg_prio,
		const struct __kernel_timespec __user *, u_abs_timeout)
{
	struct timespec64 ts, *p = NULL;
	if (u_abs_timeout) {
		int res = prepare_timeout(u_abs_timeout, &ts);      //转换为timespec64类型
		if (res)
			return res;
		p = &ts;
	}
	return do_mq_timedsend(mqdes, u_msg_ptr, msg_len, msg_prio, p);
}


static int do_mq_timedsend(mqd_t mqdes, const char __user *u_msg_ptr,
		size_t msg_len, unsigned int msg_prio,
		struct timespec64 *ts)
{
	struct fd f;
	struct inode *inode;
	struct ext_wait_queue wait;
	struct ext_wait_queue *receiver;
	struct msg_msg *msg_ptr;
	struct mqueue_inode_info *info;
	ktime_t expires, *timeout = NULL;
	struct posix_msg_tree_node *new_leaf = NULL;
	int ret = 0;
	DEFINE_WAKE_Q(wake_q);		//定义一个wake_q_head变量

	if (unlikely(msg_prio >= (unsigned long) MQ_PRIO_MAX))	//优先级错误
		return -EINVAL;

	if (ts) {
		expires = timespec64_to_ktime(*ts);	//时间类型变换，变为long long（纳秒形式）
		timeout = &expires;
	}

	audit_mq_sendrecv(mqdes, msg_len, msg_prio, ts);	//下面有源码，记录参数信息

	/*
	struct fd {
	struct file *file;
	unsigned int flags;
	};
 */
	f = fdget(mqdes);	//根据消息队列描述符，获取对应文件描述符
	if (unlikely(!f.file)) {
		ret = -EBADF;
		goto out;
	}

	inode = file_inode(f.file); 	//打开文件的inode	//return f->f_inode;
	if (unlikely(f.file->f_op != &mqueue_file_operations)) {	//文件操作
		ret = -EBADF;
		goto out_fput;
	}
	info = MQUEUE_I(inode);		//根据文件inode获取mqueue_inode_info信息

	audit_file(f.file);		//保存file的inode到audit_context结构的preallocated_names成员中

	if (unlikely(!(f.file->f_mode & FMODE_WRITE))) {
		ret = -EBADF;
		goto out_fput;
	}

	if (unlikely(msg_len > info->attr.mq_msgsize)) {	//消息长度 > 最大消息数
		ret = -EMSGSIZE;
		goto out_fput;
	}

	/* First try to allocate memory, before doing anything with
	 * existing queues. */
	msg_ptr = load_msg(u_msg_ptr, msg_len);	//存放消息到mag_ptr后的页中，与->next中
	if (IS_ERR(msg_ptr)) {
		ret = PTR_ERR(msg_ptr);
		goto out_fput;
	}
	msg_ptr->m_ts = msg_len;	//长度
	msg_ptr->m_type = msg_prio;		//优先级

	/*
	 * msg_insert really wants us to have a valid, spare node struct so
	 * it doesn't have to kmalloc a GFP_ATOMIC allocation, but it will
	 * fall back to that if necessary.
	 */
	if (!info->node_cache)
		new_leaf = kmalloc(sizeof(*new_leaf), GFP_KERNEL);

	spin_lock(&info->lock);	//上锁

	if (!info->node_cache && new_leaf) {	//node_cache为NULL， new_lead已分配
		/* Save our speculative allocation into the cache */
		INIT_LIST_HEAD(&new_leaf->msg_list);
		info->node_cache = new_leaf;
		new_leaf = NULL;		//new_leaf赋给node_cache
	} else {
		kfree(new_leaf);
	}

	if (info->attr.mq_curmsgs == info->attr.mq_maxmsg) {	//队列中消息数==最大消息数
		if (f.file->f_flags & O_NONBLOCK) {		//非阻塞
			ret = -EAGAIN;
		} else {
			wait.task = current;		//wait为局部变量
			wait.msg = (void *) msg_ptr;
			wait.state = STATE_NONE;
			ret = wq_sleep(info, SEND, timeout, &wait);	//待分析
			/*
			 * wq_sleep must be called with info->lock held, and
			 * returns with the lock released
			 */
			goto out_free;
		}
	} else {
		receiver = wq_get_first_waiter(info, RECV);		//返回消息接收者 info的e_wait_q成员
		if (receiver) {		//存在消息接收者
			pipelined_send(&wake_q, info, msg_ptr, receiver);
		} else {		//不存在接收者，将消息放入队列
			/* adds message to the queue */
			ret = msg_insert(msg_ptr, info);
			if (ret)
				goto out_unlock;
			__do_notify(info);
		}
		inode->i_atime = inode->i_mtime = inode->i_ctime =
				current_time(inode);
	}
out_unlock:
	spin_unlock(&info->lock);
	wake_up_q(&wake_q);
out_free:
	if (ret)
		free_msg(msg_ptr);
out_fput:
	fdput(f);
out:
	return ret;
}

/*
 * Returns waiting task that should be serviced first or NULL if none exists
 */
static struct ext_wait_queue *wq_get_first_waiter(
		struct mqueue_inode_info *info, int sr)
{
	struct list_head *ptr;

	ptr = info->e_wait_q[sr].list.prev;
	if (ptr == &info->e_wait_q[sr].list)
		return NULL;
	return list_entry(ptr, struct ext_wait_queue, list);
}


static inline void audit_mq_sendrecv(mqd_t mqdes, size_t msg_len, unsigned int msg_prio, const struct timespec64 *abs_timeout)
{
	if (unlikely(!audit_dummy_context()))	//如果进程的audit_context非NULL
		__audit_mq_sendrecv(mqdes, msg_len, msg_prio, abs_timeout);
}

static inline bool audit_dummy_context(void)
{
	void *p = audit_context();
	return !p || *(int *)p;
}

static inline struct audit_context *audit_context(void)
{
	return current->audit_context;
}

/**
 * __audit_mq_sendrecv - record audit data for a POSIX MQ timed send/receive
 * @mqdes: MQ descriptor
 * @msg_len: Message length
 * @msg_prio: Message priority
 * @abs_timeout: Message timeout in absolute time
 * 记录信息到进程的audit_text成员
 */
void __audit_mq_sendrecv(mqd_t mqdes, size_t msg_len, unsigned int msg_prio,
			const struct timespec64 *abs_timeout)
{
	struct audit_context *context = audit_context();	//进程的audit_context
	struct timespec64 *p = &context->mq_sendrecv.abs_timeout;

	if (abs_timeout)
		memcpy(p, abs_timeout, sizeof(*p));
	else
		memset(p, 0, sizeof(*p));

	context->mq_sendrecv.mqdes = mqdes;
	context->mq_sendrecv.msg_len = msg_len;
	context->mq_sendrecv.msg_prio = msg_prio;

	context->type = AUDIT_MQ_SENDRECV;
}

static inline struct mqueue_inode_info *MQUEUE_I(struct inode *inode)
{
	return container_of(inode, struct mqueue_inode_info, vfs_inode);	//计算得到mqueue_inode_info结构的首地址
}

#define container_of(ptr, type, member) \
    (type *)((char *)(ptr) - (char *) &((type *)0)->member)

static inline void audit_file(struct file *file)
{
	if (unlikely(!audit_dummy_context()))	//如果audit_context成员非空
		__audit_file(file);
}

void __audit_file(const struct file *file)
{
	__audit_inode(NULL, file->f_path.dentry, 0);	//指向目录项
}

struct audit_entry {
	struct list_head	list;
	struct rcu_head		rcu;
	struct audit_krule	rule;
};

void __audit_inode(struct filename *name, const struct dentry *dentry,
		   unsigned int flags)
{
	struct audit_context *context = audit_context();
	struct inode *inode = d_backing_inode(dentry);	//获取d_inode成员 目录的inode
	struct audit_names *n;
	bool parent = flags & AUDIT_INODE_PARENT;
	struct audit_entry *e;
	struct list_head *list = &audit_filter_list[AUDIT_FILTER_FS];	//list_head只有前后指针 List为第7个（audit_fs=6)
	int i;														//audit_filter_list 一个list_head数组（7个list）

	if (!context->in_syscall)	//该值为1表示任务在系统调用中
		return;

	rcu_read_lock();		//读取audit_filter_list数组 读锁
	if (!list_empty(list)) {		//list非空
		list_for_each_entry_rcu(e, list, list) {		//遍历结构e（包含list_head)  define一个for循环
			for (i = 0; i < e->rule.field_count; i++) {
				struct audit_field *f = &e->rule.fields[i];

				if (f->type == AUDIT_FSTYPE
				    && audit_comparator(inode->i_sb->s_magic,
							f->op, f->val)
				    && e->rule.action == AUDIT_NEVER) {
					rcu_read_unlock();
					return;
				}
			}
		}
	}
	rcu_read_unlock();

	if (!name)
		goto out_alloc;

	/*
	 * If we have a pointer to an audit_names entry already, then we can
	 * just use it directly if the type is correct.
	 */
	n = name->aname;
	if (n) {
		if (parent) {
			if (n->type == AUDIT_TYPE_PARENT ||
			    n->type == AUDIT_TYPE_UNKNOWN)
				goto out;
		} else {
			if (n->type != AUDIT_TYPE_PARENT)
				goto out;
		}
	}

	list_for_each_entry_reverse(n, &context->names_list, list) {
		if (n->ino) {
			/* valid inode number, use that for the comparison */
			if (n->ino != inode->i_ino ||
			    n->dev != inode->i_sb->s_dev)
				continue;
		} else if (n->name) {
			/* inode number has not been set, check the name */
			if (strcmp(n->name->name, name->name))
				continue;
		} else
			/* no inode and no name (?!) ... this is odd ... */
			continue;

		/* match the correct record type */
		if (parent) {
			if (n->type == AUDIT_TYPE_PARENT ||
			    n->type == AUDIT_TYPE_UNKNOWN)
				goto out;
		} else {
			if (n->type != AUDIT_TYPE_PARENT)
				goto out;
		}
	}

out_alloc:
	/* unable to find an entry with both a matching name and type */
	n = audit_alloc_name(context, AUDIT_TYPE_UNKNOWN);	//0
	if (!n)
		return;
	if (name) {
		n->name = name;
		name->refcnt++;
	}

out:
	if (parent) {
		n->name_len = n->name ? parent_len(n->name->name) : AUDIT_NAME_FULL;
		n->type = AUDIT_TYPE_PARENT;
		if (flags & AUDIT_INODE_HIDDEN)
			n->hidden = true;
	} else {
		n->name_len = AUDIT_NAME_FULL;
		n->type = AUDIT_TYPE_NORMAL;
	}
	handle_path(dentry);
	audit_copy_inode(n, dentry, inode, flags & AUDIT_INODE_NOEVAL);	//保存inode到audit_names
}

#define DATALEN_MSG	((size_t)PAGE_SIZE-sizeof(struct msg_msg))

struct msg_msg *load_msg(const void __user *src, size_t len)
{
	struct msg_msg *msg;
	struct msg_msgseg *seg;
	int err = -EFAULT;
	size_t alen;

	msg = alloc_msg(len);	//分配内存
	if (msg == NULL)
		return ERR_PTR(-ENOMEM);

	alen = min(len, DATALEN_MSG);
	if (copy_from_user(msg + 1, src, alen))
		goto out_err;

	for (seg = msg->next; seg != NULL; seg = seg->next) {
		len -= alen;
		src = (char __user *)src + alen;
		alen = min(len, DATALEN_SEG);
		if (copy_from_user(seg + 1, src, alen))
			goto out_err;
	}

	err = security_msg_msg_alloc(msg);
	if (err)
		goto out_err;

	return msg;

out_err:
	free_msg(msg);
	return ERR_PTR(err);
}


static struct msg_msg *alloc_msg(size_t len)
{
	struct msg_msg *msg;
	struct msg_msgseg **pseg;
	size_t alen;

	alen = min(len, DATALEN_MSG);
	msg = kmalloc(sizeof(*msg) + alen, GFP_KERNEL_ACCOUNT);
	if (msg == NULL)
		return NULL;

	msg->next = NULL;
	msg->security = NULL;

	len -= alen;
	pseg = &msg->next;
	while (len > 0) {	//len超过最大长度
		struct msg_msgseg *seg;

		cond_resched();

		alen = min(len, DATALEN_SEG);
		seg = kmalloc(sizeof(*seg) + alen, GFP_KERNEL_ACCOUNT);
		if (seg == NULL)
			goto out_err;
		*pseg = seg;
		seg->next = NULL;
		pseg = &seg->next;
		len -= alen;
	}

	return msg;

out_err:
	free_msg(msg);
	return NULL;
}


