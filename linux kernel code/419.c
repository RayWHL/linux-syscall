SYSCALL_DEFINE5(mq_timedreceive, mqd_t, mqdes, char __user *, u_msg_ptr,
		size_t, msg_len, unsigned int __user *, u_msg_prio,
		const struct __kernel_timespec __user *, u_abs_timeout)
{
	struct timespec64 ts, *p = NULL;
	if (u_abs_timeout) {
		int res = prepare_timeout(u_abs_timeout, &ts);      //转换为timespec64类型
		if (res)
			return res;
		p = &ts;
	}
	return do_mq_timedreceive(mqdes, u_msg_ptr, msg_len, u_msg_prio, p);
}


static int do_mq_timedreceive(mqd_t mqdes, char __user *u_msg_ptr,
		size_t msg_len, unsigned int __user *u_msg_prio,
		struct timespec64 *ts)
{
	ssize_t ret;
	struct msg_msg *msg_ptr;
	struct fd f;
	struct inode *inode;
	struct mqueue_inode_info *info;
	struct ext_wait_queue wait;
	ktime_t expires, *timeout = NULL;
	struct posix_msg_tree_node *new_leaf = NULL;

	if (ts) {
		expires = timespec64_to_ktime(*ts);
		timeout = &expires;
	}

	audit_mq_sendrecv(mqdes, msg_len, 0, ts);   //记录参数信息到audit_context

	f = fdget(mqdes);       //获得对应文件描述符
	if (unlikely(!f.file)) {
		ret = -EBADF;
		goto out;
	}

	inode = file_inode(f.file);         //获得文件inode
	if (unlikely(f.file->f_op != &mqueue_file_operations)) {
		ret = -EBADF;
		goto out_fput;
	}
	info = MQUEUE_I(inode);    //获得消息队列的mequeue_inode_info结构
	audit_file(f.file);         //保存inode

	if (unlikely(!(f.file->f_mode & FMODE_READ))) {
		ret = -EBADF;
		goto out_fput;
	}

	/* checks if buffer is big enough */
	if (unlikely(msg_len < info->attr.mq_msgsize)) {
		ret = -EMSGSIZE;        //缓冲区是否足够
		goto out_fput;
	}

	/*
	 * msg_insert really wants us to have a valid, spare node struct so
	 * it doesn't have to kmalloc a GFP_ATOMIC allocation, but it will
	 * fall back to that if necessary.
	 */
	if (!info->node_cache)          //如果node_cache为NULL，分配该成员的内存
		new_leaf = kmalloc(sizeof(*new_leaf), GFP_KERNEL);

	spin_lock(&info->lock);

	if (!info->node_cache && new_leaf) {
		/* Save our speculative allocation into the cache */
		INIT_LIST_HEAD(&new_leaf->msg_list);
		info->node_cache = new_leaf;
	} else {
		kfree(new_leaf);
	}

	if (info->attr.mq_curmsgs == 0) {
		if (f.file->f_flags & O_NONBLOCK) {
			spin_unlock(&info->lock);
			ret = -EAGAIN;
		} else {
			wait.task = current;
			wait.state = STATE_NONE;
			ret = wq_sleep(info, RECV, timeout, &wait);
			msg_ptr = wait.msg;
		}
	} else {
		DEFINE_WAKE_Q(wake_q);

		msg_ptr = msg_get(info);

		inode->i_atime = inode->i_mtime = inode->i_ctime =
				current_time(inode);

		/* There is now free space in queue. */
		pipelined_receive(&wake_q, info);
		spin_unlock(&info->lock);
		wake_up_q(&wake_q);
		ret = 0;
	}
	if (ret == 0) {
		ret = msg_ptr->m_ts;

		if ((u_msg_prio && put_user(msg_ptr->m_type, u_msg_prio)) ||
			store_msg(u_msg_ptr, msg_ptr, msg_ptr->m_ts)) {
			ret = -EFAULT;
		}
		free_msg(msg_ptr);
	}
out_fput:
	fdput(f);
out:
	return ret;
}
