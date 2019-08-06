
/*
 * Passed in for io_uring_setup(2). Copied back with updated info on success
 * 其中，flags、sq_thread_cpu、sq_thread_idle 属于输入参数，用于定义 io_uring 在内核中的行为。
 * 其他参数属于输出参数，由内核负责设置。
 */
struct io_uring_params {
	__u32 sq_entries;
	__u32 cq_entries;
	__u32 flags;
	__u32 sq_thread_cpu;
	__u32 sq_thread_idle;
	__u32 resv[5];
	struct io_sqring_offsets sq_off;
	struct io_cqring_offsets cq_off;
};

SYSCALL_DEFINE2(io_uring_setup, u32, entries,
		struct io_uring_params __user *, params)
{
	return io_uring_setup(entries, params);
}
/*
 * Sets up an aio uring context, and returns the fd. Applications asks for a
 * ring size, we return the actual sq/cq ring sizes (among other things) in the
 * params structure passed in.
 * 如果在调用 io_uring_setup 时设置了 IORING_SETUP_SQPOLL 的 flag，内核会额外启动一个内核线程，我们称作 SQ 线程
 * 
 * 如果使用了 IORING_SETUP_SQPOLL 参数，IO 收割也不需要系统调用的参与。由于内核和用户态共享内存，
 * 所以收割的时候，用户态遍历 [cring->head, cring->tail) 区间，这是已经完成的 IO 队列，然后找到相应的 CQE 并进行处理，
 * 最后移动 head 指针到 tail，IO 收割就到此结束了。
 * 
 * IORING_SETUP_IOPOLL
 * 这个功能让内核采用 Polling 的模式收割 Block 层的请求。当没有使用 SQ 线程时，io_uring_enter 函数会主动的 Poll，
 * 以检查提交给 Block 层的请求是否已经完成，而不是挂起，并等待 Block 层完成后再被唤醒。使用 SQ 线程时也是同理。
 */
static long io_uring_setup(u32 entries, struct io_uring_params __user *params)
{
	struct io_uring_params p;
	long ret;
	int i;

	if (copy_from_user(&p, params, sizeof(p)))  //拷贝到内核空间
		return -EFAULT;
	for (i = 0; i < ARRAY_SIZE(p.resv); i++) {
		if (p.resv[i])
			return -EINVAL;
	}


	if (p.flags & ~(IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL |
			IORING_SETUP_SQ_AFF))
		return -EINVAL;

	ret = io_uring_create(entries, &p);		//创建一系列的数据结构
	if (ret < 0)
		return ret;

	if (copy_to_user(params, &p, sizeof(p)))	//将结果复制到用户空间
		return -EFAULT;

	return ret;
}

static int io_uring_create(unsigned entries, struct io_uring_params *p)
{
	struct user_struct *user = NULL;
	struct io_ring_ctx *ctx;
	bool account_mem;
	int ret;

	if (!entries || entries > IORING_MAX_ENTRIES)   //为0或者大于最大深度
		return -EINVAL;

	/*
	 * Use twice as many entries for the CQ ring. It's possible for the
	 * application to drive a higher depth than the size of the SQ ring,
	 * since the sqes are only used at submission time. This allows for
	 * some flexibility in overcommitting a bit.
	 */
	p->sq_entries = roundup_pow_of_two(entries);    //最接近的最大2的指数次幂
	p->cq_entries = 2 * p->sq_entries;

	user = get_uid(current_user()); //通过current->cred->user，并将引用计数加一
	account_mem = !capable(CAP_IPC_LOCK);   //确定当前进程是否有 CAP_IPC_LOCK 功能

	if (account_mem) {  //没有
		ret = io_account_mem(user,
				ring_pages(p->sq_entries, p->cq_entries));  //扩展pages 修改user结构
		if (ret) {
			free_uid(user);
			return ret;
		}
	}

	ctx = io_ring_ctx_alloc(p);         //初始化ctx
	if (!ctx) {
		if (account_mem)
			io_unaccount_mem(user, ring_pages(p->sq_entries,
								p->cq_entries));
		free_uid(user);
		return -ENOMEM;
	}
	ctx->compat = in_compat_syscall();
	ctx->account_mem = account_mem;
	ctx->user = user;

	ret = io_allocate_scq_urings(ctx, p);		//创建sq cq队列
	if (ret)
		goto err;

	ret = io_sq_offload_start(ctx, p);		//如果flag满足条件，创建一个新线程
	if (ret)
		goto err;

	ret = io_uring_get_fd(ctx);			//获得一个文件描述符
	if (ret < 0)
		goto err;

	memset(&p->sq_off, 0, sizeof(p->sq_off));
	p->sq_off.head = offsetof(struct io_sq_ring, r.head);
	p->sq_off.tail = offsetof(struct io_sq_ring, r.tail);
	p->sq_off.ring_mask = offsetof(struct io_sq_ring, ring_mask);
	p->sq_off.ring_entries = offsetof(struct io_sq_ring, ring_entries);
	p->sq_off.flags = offsetof(struct io_sq_ring, flags);
	p->sq_off.dropped = offsetof(struct io_sq_ring, dropped);
	p->sq_off.array = offsetof(struct io_sq_ring, array);

	memset(&p->cq_off, 0, sizeof(p->cq_off));
	p->cq_off.head = offsetof(struct io_cq_ring, r.head);
	p->cq_off.tail = offsetof(struct io_cq_ring, r.tail);
	p->cq_off.ring_mask = offsetof(struct io_cq_ring, ring_mask);
	p->cq_off.ring_entries = offsetof(struct io_cq_ring, ring_entries);
	p->cq_off.overflow = offsetof(struct io_cq_ring, overflow);
	p->cq_off.cqes = offsetof(struct io_cq_ring, cqes);
	return ret;
err:
	io_ring_ctx_wait_and_kill(ctx);
	return ret;
}

static struct io_ring_ctx *io_ring_ctx_alloc(struct io_uring_params *p)
{
	struct io_ring_ctx *ctx;
	int i;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);        //内核空间分配ctx
	if (!ctx)
		return NULL;

	if (percpu_ref_init(&ctx->refs, io_ring_ctx_ref_free, 0, GFP_KERNEL)) { //初始化refs
		kfree(ctx);
		return NULL;
	}

	ctx->flags = p->flags;
	init_waitqueue_head(&ctx->cq_wait);
	init_completion(&ctx->ctx_done);
	mutex_init(&ctx->uring_lock);
	init_waitqueue_head(&ctx->wait);
	for (i = 0; i < ARRAY_SIZE(ctx->pending_async); i++) {
		spin_lock_init(&ctx->pending_async[i].lock);
		INIT_LIST_HEAD(&ctx->pending_async[i].list);
		atomic_set(&ctx->pending_async[i].cnt, 0);
	}
	spin_lock_init(&ctx->completion_lock);
	INIT_LIST_HEAD(&ctx->poll_list);
	INIT_LIST_HEAD(&ctx->cancel_list);
	return ctx;
}
