SYSCALL_DEFINE6(io_uring_enter, unsigned int, fd, u32, to_submit,
		u32, min_complete, u32, flags, const sigset_t __user *, sig,
		size_t, sigsz)
{
	struct io_ring_ctx *ctx;
	long ret = -EBADF;
	int submitted = 0;
	struct fd f;

	if (flags & ~(IORING_ENTER_GETEVENTS | IORING_ENTER_SQ_WAKEUP))
		return -EINVAL;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	ret = -EOPNOTSUPP;
	if (f.file->f_op != &io_uring_fops)
		goto out_fput;

	ret = -ENXIO;
	ctx = f.file->private_data;     //从文件file结构中获得ctx
	if (!percpu_ref_tryget(&ctx->refs))
		goto out_fput;

	/*
	 * For SQ polling, the thread will do all submissions and completions.
	 * Just return the requested submit count, and wake the thread if
	 * we were asked to.
	 */
	if (ctx->flags & IORING_SETUP_SQPOLL) {     //如果有该标记
		if (flags & IORING_ENTER_SQ_WAKEUP)
			wake_up(&ctx->sqo_wait);
		submitted = to_submit;
		goto out_ctx;
	}

	ret = 0;
	if (to_submit) {
		to_submit = min(to_submit, ctx->sq_entries);   

		mutex_lock(&ctx->uring_lock);
		submitted = io_ring_submit(ctx, to_submit);     //提交请求
		mutex_unlock(&ctx->uring_lock);
	}
	if (flags & IORING_ENTER_GETEVENTS) {
		unsigned nr_events = 0;

		min_complete = min(min_complete, ctx->cq_entries);

		if (ctx->flags & IORING_SETUP_IOPOLL) {
			mutex_lock(&ctx->uring_lock);
			ret = io_iopoll_check(ctx, &nr_events, min_complete);
			mutex_unlock(&ctx->uring_lock);
		} else {
			ret = io_cqring_wait(ctx, min_complete, sig, sigsz);
		}
	}

out_ctx:
	io_ring_drop_ctx_refs(ctx, 1);
out_fput:
	fdput(f);
	return submitted ? submitted : ret;
}

static int io_ring_submit(struct io_ring_ctx *ctx, unsigned int to_submit)
{
	struct io_submit_state state, *statep = NULL;
	int i, submit = 0;

	if (to_submit > IO_PLUG_THRESHOLD) {
		io_submit_state_start(&state, ctx, to_submit);
		statep = &state;
	}

	for (i = 0; i < to_submit; i++) {
		struct sqe_submit s;
		int ret;

		if (!io_get_sqring(ctx, &s))    //从sq获取一个条目 ctx->sq_sqes
			break;

		s.has_user = true;
		s.needs_lock = false;
		s.needs_fixed_file = false;
		submit++;

		ret = io_submit_sqe(ctx, &s, statep);
		if (ret)
			io_cqring_add_event(ctx, s.sqe->user_data, ret, 0);
	}
	io_commit_sqring(ctx);

	if (statep)
		io_submit_state_end(statep);

	return submit;
}

