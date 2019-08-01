typedef __kernel_ulong_t aio_context_t;     //unsigned long
//aio_context_t 即 AIO 上下文句柄，该结构体对应内核中的一个 struct kioctx 结构，
//用来给一组异步 IO 请求提供一个上下文环境，每个进程可以有多个 aio_context_t，io_setup 的第一个参数声明了同时驻留在内核中的异步 
//IO 上下文数量



#define _NSIG		64
#define _NSIG_BPW	64
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

typedef unsigned long old_sigset_t;		/* at least 32 bits */

typedef struct {
	unsigned long sig[_NSIG_WORDS];
} sigset_t;

struct __aio_sigset {
	const sigset_t __user	*sigmask;
	size_t		sigsetsize;
};

/*
其中，struct iocb主要包含以下字段：
__u16???? aio_lio_opcode;???? /* 请求类型（如：IOCB_CMD_PREAD=读、IOCB_CMD_PWRITE=写、等） *
__u32???? aio_fildes;???????? * 要被操作的fd *
__u64???? aio_buf;??????????? * 读写操作对应的内存buffer *
__u64???? aio_nbytes;???????? /* 需要读写的字节长度 *
__s64???? aio_offset;???????? /* 读写操作对应的文件偏移 *
__u64???? aio_data;?????????? /* 请求可携带的私有数据（在io_getevents时能够从io_event结果中取得） *
__u32???? aio_flags;????????? /* 可选IOCB_FLAG_RESFD标记，表示异步请求处理完成时使用eventfd进行通知（百度一下） *
__u32???? aio_resfd;????????? /* 有IOCB_FLAG_RESFD标记时，接收通知的eventfd *

其中，struct io_event 主要包含以下字段：
__u64???? data;?????????????? /* 对应iocb的aio_data的值 *
__u64???? obj;??????????????? /* 指向对应iocb的指针 *
__s64???? res;??????????????? /* 对应IO请求的结果（>=0: 相当于对应的同步调用的返回值；<0: -errno） *

io_context_t 句柄在内核中对应一个struct kioctx 结构，用来给一组异步IO请求提供一个上下文。其主要包含以下字段：
struct mm_struct*???? mm;???????????? /* 调用者进程对应的内存管理结构（代表了调用者的虚拟地址空间） *
unsigned long???????? user_id;??????? /* 上下文ID，也就是io_context_t句柄的值（等于ring_info.mmap_base） *
struct hlist_node???? list;?????????? /* 属于同一地址空间的所有kioctx结构通过这个list串连起来，链表头是mm->ioctx_list *
wait_queue_head_t???? wait;?????????? /* 等待队列（io_getevents系统调用可能需要等待，调用者就在该等待队列上睡眠） *
int?????????????????? reqs_active;??? /* 进行中的请求数目 *
struct list_head????? active_reqs;??? /* 进行中的请求队列 *
unsigned????????????? max_reqs;?????? /* 最大请求数（对应io_setup调用的int maxevents参数） *
struct list_head????? run_list;?????? /* 需要aio线程处理的请求列表（某些情况下，IO请求可能交给aio线程来提交） *
struct delayed_work?? wq;???????????? /* 延迟任务队列（当需要aio线程处理请求时，将wq挂入aio线程对应的请求队列） *
struct aio_ring_info? ring_info;????? /* 存放请求结果io_event结构的ring buffer *

其中，这个 aio_ring_info 结构比较值得一提，它是用于存放请求结果io_event结构的ring buffer。它主要包含了如下字段：
unsigned long?? mmap_base;?????? /* ring buffer的地始地址 *
unsigned long?? mmap_size;?????? /* ring buffer分配空间的大小 *
struct page**?? ring_pages;????? /* ring buffer对应的page数组 *
long??????????? nr_pages;??????? /* 分配空间对应的页面数目（nr_pages * PAGE_SIZE = mmap_size） *
unsigned??????? nr, tail;??????? /* 包含io_event的数目及存取游标 *

*/

/* read() from /dev/aio returns these structures. */
struct io_event {
	__u64		data;		/* the data field from the iocb */
	__u64		obj;		/* what iocb this event came from */
	__s64		res;		/* result code for this event */
	__s64		res2;		/* secondary result */
};


SYSCALL_DEFINE6(io_pgetevents,
		aio_context_t, ctx_id,
		long, min_nr,
		long, nr,
		struct io_event __user *, events,
		struct __kernel_timespec __user *, timeout,
		const struct __aio_sigset __user *, usig)
{
	struct __aio_sigset	ksig = { NULL, };
	sigset_t		ksigmask, sigsaved;
	struct timespec64	ts;
	int ret;

	if (timeout && unlikely(get_timespec64(&ts, timeout)))
		return -EFAULT;

	if (usig && copy_from_user(&ksig, usig, sizeof(ksig)))
		return -EFAULT;

	ret = set_user_sigmask(ksig.sigmask, &ksigmask, &sigsaved, ksig.sigsetsize);    //1、4参数为输入，2、3参数为输出
	if (ret)                                         //将sigmask拷贝到ksigmask ， sigsaved指向current->blocked以保存原值
		return ret;                                  //设置currnet->blocked为ksigmask 修改进程阻塞信号


	ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout ? &ts : NULL);
	restore_user_sigmask(ksig.sigmask, &sigsaved);      //保存原信号
	if (signal_pending(current) && !ret)
		ret = -ERESTARTNOHAND;

	return ret;
}


int set_user_sigmask(const sigset_t __user *usigmask, sigset_t *set,
		     sigset_t *oldset, size_t sigsetsize)
{
	if (!usigmask)
		return 0;

	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;
	if (copy_from_user(set, usigmask, sizeof(sigset_t)))
		return -EFAULT;

	*oldset = current->blocked;
	set_current_blocked(set);

	return 0;
}

static long do_io_getevents(aio_context_t ctx_id,
		long min_nr,
		long nr,
		struct io_event __user *events,
		struct timespec64 *ts)
{
	ktime_t until = ts ? timespec64_to_ktime(*ts) : KTIME_MAX;
	struct kioctx *ioctx = lookup_ioctx(ctx_id);
	long ret = -EINVAL;

	if (likely(ioctx)) {
		if (likely(min_nr <= nr && min_nr >= 0))
			ret = read_events(ioctx, min_nr, nr, events, until);
		percpu_ref_put(&ioctx->users);
	}

	return ret;
}

static long read_events(struct kioctx *ctx, long min_nr, long nr,
			struct io_event __user *event,
			ktime_t until)
{
	long ret = 0;

	/*
	 * Note that aio_read_events() is being called as the conditional - i.e.
	  we're calling it after prepare_to_wait() has set task state to
	  TASK_INTERRUPTIBLE.
	 
	  But aio_read_events() can block, and if it blocks it's going to flip
	  the task state back to TASK_RUNNING.
	 
	  This should be ok, provided it doesn't flip the state back to
	  TASK_RUNNING and return 0 too much - that causes us to spin. That
	  will only happen if the mutex_lock() call blocks, and we then find
	  the ringbuffer empty. So in practice we should be ok, but it's
	  something to be aware of when touching this code.
	 */
	if (until == 0)
		aio_read_events(ctx, min_nr, nr, event, &ret);
	else
		wait_event_interruptible_hrtimeout(ctx->wait,
				aio_read_events(ctx, min_nr, nr, event, &ret),
				until);
	return ret;
}

/**
 * wait_event_interruptible_hrtimeout - sleep until a condition gets true or a timeout elapses
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, as a ktime_t
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function returns 0 if @condition became true, -ERESTARTSYS if it was
 * interrupted by a signal, or -ETIME if the timeout elapsed.
 */
#define wait_event_interruptible_hrtimeout(wq, condition, timeout)		\
({										\
	long __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_hrtimeout(wq, condition, timeout,		\
					       TASK_INTERRUPTIBLE);		\
	__ret;									\
})


static bool aio_read_events(struct kioctx *ctx, long min_nr, long nr,
			    struct io_event __user *event, long *i)
{
	long ret = aio_read_events_ring(ctx, event + *i, nr - *i);

	if (ret > 0)
		*i += ret;

	if (unlikely(atomic_read(&ctx->dead)))
		ret = -EINVAL;

	if (!*i)
		*i = ret;

	return ret < 0 || *i >= min_nr;
}

/* aio_read_events_ring
 *	Pull an event off of the ioctx's event ring.  Returns the number of
 *	events fetched
 */
static long aio_read_events_ring(struct kioctx *ctx,
				 struct io_event __user *event, long nr)
{
	struct aio_ring *ring;
	unsigned head, tail, pos;
	long ret = 0;
	int copy_ret;

	/*
	 * The mutex can block and wake us up and that will cause
	 * wait_event_interruptible_hrtimeout() to schedule without sleeping
	 * and repeat. This should be rare enough that it doesn't cause
	 * peformance issues. See the comment in read_events() for more detail.
	 */
	sched_annotate_sleep();
	mutex_lock(&ctx->ring_lock);

	/* Access to ->ring_pages here is protected by ctx->ring_lock. */
	ring = kmap_atomic(ctx->ring_pages[0]);
	head = ring->head;
	tail = ring->tail;
	kunmap_atomic(ring);

	/*
	 * Ensure that once we've read the current tail pointer, that
	 * we also see the events that were stored up to the tail.
	 */
	smp_rmb();

	pr_debug("h%u t%u m%u\n", head, tail, ctx->nr_events);

	if (head == tail)
		goto out;

	head %= ctx->nr_events;
	tail %= ctx->nr_events;

	while (ret < nr) {
		long avail;
		struct io_event *ev;
		struct page *page;

		avail = (head <= tail ?  tail : ctx->nr_events) - head;
		if (head == tail)
			break;

		pos = head + AIO_EVENTS_OFFSET;
		page = ctx->ring_pages[pos / AIO_EVENTS_PER_PAGE];
		pos %= AIO_EVENTS_PER_PAGE;

		avail = min(avail, nr - ret);
		avail = min_t(long, avail, AIO_EVENTS_PER_PAGE - pos);

		ev = kmap(page);
		copy_ret = copy_to_user(event + ret, ev + pos,
					sizeof(*ev) * avail);
		kunmap(page);

		if (unlikely(copy_ret)) {
			ret = -EFAULT;
			goto out;
		}

		ret += avail;
		head += avail;
		head %= ctx->nr_events;
	}

	ring = kmap_atomic(ctx->ring_pages[0]);
	ring->head = head;
	kunmap_atomic(ring);
	flush_dcache_page(ctx->ring_pages[0]);

	pr_debug("%li  h%u t%u\n", ret, head, tail);
out:
	mutex_unlock(&ctx->ring_lock);

	return ret;
}