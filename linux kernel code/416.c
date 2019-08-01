typedef __kernel_ulong_t aio_context_t;     //unsigned long
//aio_context_t �� AIO �����ľ�����ýṹ���Ӧ�ں��е�һ�� struct kioctx �ṹ��
//������һ���첽 IO �����ṩһ�������Ļ�����ÿ�����̿����ж�� aio_context_t��io_setup �ĵ�һ������������ͬʱפ�����ں��е��첽 
//IO ����������



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
���У�struct iocb��Ҫ���������ֶΣ�
__u16???? aio_lio_opcode;???? /* �������ͣ��磺IOCB_CMD_PREAD=����IOCB_CMD_PWRITE=д���ȣ� *
__u32???? aio_fildes;???????? * Ҫ��������fd *
__u64???? aio_buf;??????????? * ��д������Ӧ���ڴ�buffer *
__u64???? aio_nbytes;???????? /* ��Ҫ��д���ֽڳ��� *
__s64???? aio_offset;???????? /* ��д������Ӧ���ļ�ƫ�� *
__u64???? aio_data;?????????? /* �����Я����˽�����ݣ���io_geteventsʱ�ܹ���io_event�����ȡ�ã� *
__u32???? aio_flags;????????? /* ��ѡIOCB_FLAG_RESFD��ǣ���ʾ�첽���������ʱʹ��eventfd����֪ͨ���ٶ�һ�£� *
__u32???? aio_resfd;????????? /* ��IOCB_FLAG_RESFD���ʱ������֪ͨ��eventfd *

���У�struct io_event ��Ҫ���������ֶΣ�
__u64???? data;?????????????? /* ��Ӧiocb��aio_data��ֵ *
__u64???? obj;??????????????? /* ָ���Ӧiocb��ָ�� *
__s64???? res;??????????????? /* ��ӦIO����Ľ����>=0: �൱�ڶ�Ӧ��ͬ�����õķ���ֵ��<0: -errno�� *

io_context_t ������ں��ж�Ӧһ��struct kioctx �ṹ��������һ���첽IO�����ṩһ�������ġ�����Ҫ���������ֶΣ�
struct mm_struct*???? mm;???????????? /* �����߽��̶�Ӧ���ڴ����ṹ�������˵����ߵ������ַ�ռ䣩 *
unsigned long???????? user_id;??????? /* ������ID��Ҳ����io_context_t�����ֵ������ring_info.mmap_base�� *
struct hlist_node???? list;?????????? /* ����ͬһ��ַ�ռ������kioctx�ṹͨ�����list��������������ͷ��mm->ioctx_list *
wait_queue_head_t???? wait;?????????? /* �ȴ����У�io_geteventsϵͳ���ÿ�����Ҫ�ȴ��������߾��ڸõȴ�������˯�ߣ� *
int?????????????????? reqs_active;??? /* �����е�������Ŀ *
struct list_head????? active_reqs;??? /* �����е�������� *
unsigned????????????? max_reqs;?????? /* �������������Ӧio_setup���õ�int maxevents������ *
struct list_head????? run_list;?????? /* ��Ҫaio�̴߳���������б�ĳЩ����£�IO������ܽ���aio�߳����ύ�� *
struct delayed_work?? wq;???????????? /* �ӳ�������У�����Ҫaio�̴߳�������ʱ����wq����aio�̶߳�Ӧ��������У� *
struct aio_ring_info? ring_info;????? /* ���������io_event�ṹ��ring buffer *

���У���� aio_ring_info �ṹ�Ƚ�ֵ��һ�ᣬ�������ڴ��������io_event�ṹ��ring buffer������Ҫ�����������ֶΣ�
unsigned long?? mmap_base;?????? /* ring buffer�ĵ�ʼ��ַ *
unsigned long?? mmap_size;?????? /* ring buffer����ռ�Ĵ�С *
struct page**?? ring_pages;????? /* ring buffer��Ӧ��page���� *
long??????????? nr_pages;??????? /* ����ռ��Ӧ��ҳ����Ŀ��nr_pages * PAGE_SIZE = mmap_size�� *
unsigned??????? nr, tail;??????? /* ����io_event����Ŀ����ȡ�α� *

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

	ret = set_user_sigmask(ksig.sigmask, &ksigmask, &sigsaved, ksig.sigsetsize);    //1��4����Ϊ���룬2��3����Ϊ���
	if (ret)                                         //��sigmask������ksigmask �� sigsavedָ��current->blocked�Ա���ԭֵ
		return ret;                                  //����currnet->blockedΪksigmask �޸Ľ��������ź�


	ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout ? &ts : NULL);
	restore_user_sigmask(ksig.sigmask, &sigsaved);      //����ԭ�ź�
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