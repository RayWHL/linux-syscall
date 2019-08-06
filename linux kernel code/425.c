
/*
 * Passed in for io_uring_setup(2). Copied back with updated info on success
 * ���У�flags��sq_thread_cpu��sq_thread_idle ����������������ڶ��� io_uring ���ں��е���Ϊ��
 * ������������������������ں˸������á�
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
 * ����ڵ��� io_uring_setup ʱ������ IORING_SETUP_SQPOLL �� flag���ں˻��������һ���ں��̣߳����ǳ��� SQ �߳�
 * 
 * ���ʹ���� IORING_SETUP_SQPOLL ������IO �ո�Ҳ����Ҫϵͳ���õĲ��롣�����ں˺��û�̬�����ڴ棬
 * �����ո��ʱ���û�̬���� [cring->head, cring->tail) ���䣬�����Ѿ���ɵ� IO ���У�Ȼ���ҵ���Ӧ�� CQE �����д���
 * ����ƶ� head ָ�뵽 tail��IO �ո�͵��˽����ˡ�
 * 
 * IORING_SETUP_IOPOLL
 * ����������ں˲��� Polling ��ģʽ�ո� Block ������󡣵�û��ʹ�� SQ �߳�ʱ��io_uring_enter ������������ Poll��
 * �Լ���ύ�� Block ��������Ƿ��Ѿ���ɣ������ǹ��𣬲��ȴ� Block ����ɺ��ٱ����ѡ�ʹ�� SQ �߳�ʱҲ��ͬ��
 */
static long io_uring_setup(u32 entries, struct io_uring_params __user *params)
{
	struct io_uring_params p;
	long ret;
	int i;

	if (copy_from_user(&p, params, sizeof(p)))  //�������ں˿ռ�
		return -EFAULT;
	for (i = 0; i < ARRAY_SIZE(p.resv); i++) {
		if (p.resv[i])
			return -EINVAL;
	}


	if (p.flags & ~(IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL |
			IORING_SETUP_SQ_AFF))
		return -EINVAL;

	ret = io_uring_create(entries, &p);		//����һϵ�е����ݽṹ
	if (ret < 0)
		return ret;

	if (copy_to_user(params, &p, sizeof(p)))	//��������Ƶ��û��ռ�
		return -EFAULT;

	return ret;
}

static int io_uring_create(unsigned entries, struct io_uring_params *p)
{
	struct user_struct *user = NULL;
	struct io_ring_ctx *ctx;
	bool account_mem;
	int ret;

	if (!entries || entries > IORING_MAX_ENTRIES)   //Ϊ0���ߴ���������
		return -EINVAL;

	/*
	 * Use twice as many entries for the CQ ring. It's possible for the
	 * application to drive a higher depth than the size of the SQ ring,
	 * since the sqes are only used at submission time. This allows for
	 * some flexibility in overcommitting a bit.
	 */
	p->sq_entries = roundup_pow_of_two(entries);    //��ӽ������2��ָ������
	p->cq_entries = 2 * p->sq_entries;

	user = get_uid(current_user()); //ͨ��current->cred->user���������ü�����һ
	account_mem = !capable(CAP_IPC_LOCK);   //ȷ����ǰ�����Ƿ��� CAP_IPC_LOCK ����

	if (account_mem) {  //û��
		ret = io_account_mem(user,
				ring_pages(p->sq_entries, p->cq_entries));  //��չpages �޸�user�ṹ
		if (ret) {
			free_uid(user);
			return ret;
		}
	}

	ctx = io_ring_ctx_alloc(p);         //��ʼ��ctx
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

	ret = io_allocate_scq_urings(ctx, p);		//����sq cq����
	if (ret)
		goto err;

	ret = io_sq_offload_start(ctx, p);		//���flag��������������һ�����߳�
	if (ret)
		goto err;

	ret = io_uring_get_fd(ctx);			//���һ���ļ�������
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

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);        //�ں˿ռ����ctx
	if (!ctx)
		return NULL;

	if (percpu_ref_init(&ctx->refs, io_ring_ctx_ref_free, 0, GFP_KERNEL)) { //��ʼ��refs
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
