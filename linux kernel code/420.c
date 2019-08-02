/* semop system calls takes an array of these. */
struct sembuf {
	unsigned short  sem_num;	/* semaphore index in array */
	short		sem_op;		/* semaphore operation */
	short		sem_flg;	/* operation flags */
};

#define SEMOPM_FAST	64  /* ~ 372 bytes on stack */

/* One sem_array data structure for each set of semaphores in the system. */
struct sem_array {
	struct kern_ipc_perm	sem_perm;	/* permissions .. see ipc.h */
	time64_t		sem_ctime;	/* create/last semctl() time */
	struct list_head	pending_alter;	/* pending operations */
						/* that alter the array */
	struct list_head	pending_const;	/* pending complex operations */
						/* that do not alter semvals */
	struct list_head	list_id;	/* undo requests on this array */
	int			sem_nsems;	/* no. of semaphores in array */
	int			complex_count;	/* pending complex operations */
	unsigned int		use_global_lock;/* >0: global lock required */

	struct sem		sems[];
} __randomize_layout;


SYSCALL_DEFINE4(semtimedop, int, semid, struct sembuf __user *, tsops,
		unsigned int, nsops, const struct __kernel_timespec __user *, timeout)
{
	return ksys_semtimedop(semid, tsops, nsops, timeout);
}

long ksys_semtimedop(int semid, struct sembuf __user *tsops,
		     unsigned int nsops, const struct __kernel_timespec __user *timeout)
{
	if (timeout) {
		struct timespec64 ts;
		if (get_timespec64(&ts, timeout))	//转换为timespec64类型
			return -EFAULT;
		return do_semtimedop(semid, tsops, nsops, &ts);
	}
	return do_semtimedop(semid, tsops, nsops, NULL);
}

static long do_semtimedop(int semid, struct sembuf __user *tsops,
		unsigned nsops, const struct timespec64 *timeout)
{
	int error = -EINVAL;
	struct sem_array *sma;
	struct sembuf fast_sops[SEMOPM_FAST];
	struct sembuf *sops = fast_sops, *sop;
	struct sem_undo *un;
	int max, locknum;
	bool undos = false, alter = false, dupsop = false;
	struct sem_queue queue;
	unsigned long dup = 0, jiffies_left = 0;
	struct ipc_namespace *ns;

	ns = current->nsproxy->ipc_ns;	//该进程ipc名称空间

	if (nsops < 1 || semid < 0)
		return -EINVAL;
	if (nsops > ns->sc_semopm)	//nsops超过最大？
		return -E2BIG;
	if (nsops > SEMOPM_FAST) {
		sops = kvmalloc_array(nsops, sizeof(*sops), GFP_KERNEL);
		if (sops == NULL)
			return -ENOMEM;
	}

	if (copy_from_user(sops, tsops, nsops * sizeof(*tsops))) {	//拷贝到内核空间
		error =  -EFAULT;
		goto out_free;
	}

	if (timeout) {
		if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
			timeout->tv_nsec >= 1000000000L) {
			error = -EINVAL;
			goto out_free;
		}
		jiffies_left = timespec64_to_jiffies(timeout);	//jiffie
	}

	max = 0;
	for (sop = sops; sop < sops + nsops; sop++) {		//alter权限 undo标记
		unsigned long mask = 1ULL << ((sop->sem_num) % BITS_PER_LONG);

		if (sop->sem_num >= max)
			max = sop->sem_num;
		if (sop->sem_flg & SEM_UNDO)
			undos = true;
		if (dup & mask) {		//dup  ul  dupsop bool
			/*
			 * There was a previous alter access that appears
			 * to have accessed the same semaphore, thus use
			 * the dupsop logic. "appears", because the detection
			 * can only check % BITS_PER_LONG.
			 */
			dupsop = true;
		}
		if (sop->sem_op != 0) {
			alter = true;
			dup |= mask;
		}
	}

	if (undos) {
		/* On success, find_alloc_undo takes the rcu_read_lock */
		un = find_alloc_undo(ns, semid);	//取得undo list 没有则创建一个
		if (IS_ERR(un)) {
			error = PTR_ERR(un);
			goto out_free;
		}
	} else {
		un = NULL;
		rcu_read_lock();
	}

	sma = sem_obtain_object_check(ns, semid);		//获得信号集描述符对应的sem_array结构
	if (IS_ERR(sma)) {
		rcu_read_unlock();
		error = PTR_ERR(sma);
		goto out_free;
	}

	error = -EFBIG;
	if (max >= sma->sem_nsems) {	//信号序号过大
		rcu_read_unlock();
		goto out_free;
	}

	error = -EACCES;
	if (ipcperms(ns, &sma->sem_perm, alter ? S_IWUGO : S_IRUGO)) {	//检查ipc权限
		rcu_read_unlock();
		goto out_free;
	}

	error = security_sem_semop(&sma->sem_perm, sops, nsops, alter);		// call_int_hook
	if (error) {
		rcu_read_unlock();
		goto out_free;
	}

	error = -EIDRM;
	locknum = sem_lock(sma, sops, nsops);		//为信号量加锁
	/*
	 * We eventually might perform the following check in a lockless
	 * fashion, considering ipc_valid_object() locking constraints.
	 * If nsops == 1 and there is no contention for sem_perm.lock, then
	 * only a per-semaphore lock is held and it's OK to proceed with the
	 * check below. More details on the fine grained locking scheme
	 * entangled here and why it's RMID race safe on comments at sem_lock()
	 */
	if (!ipc_valid_object(&sma->sem_perm))
		goto out_unlock_free;
	/*
	 * semid identifiers are not unique - find_alloc_undo may have
	 * allocated an undo structure, it was invalidated by an RMID
	 * and now a new array with received the same id. Check and fail.
	 * This case can be detected checking un->semid. The existence of
	 * "un" itself is guaranteed by rcu.
	 */
	if (un && un->semid == -1)
		goto out_unlock_free;

	queue.sops = sops;
	queue.nsops = nsops;
	queue.undo = un;
	queue.pid = task_tgid(current);
	queue.alter = alter;
	queue.dupsop = dupsop;

	error = perform_atomic_semop(sma, &queue);	//尝试执行操作，返回0：possible 1:impossible <0:error
	if (error == 0) { /* non-blocking succesfull path */
		DEFINE_WAKE_Q(wake_q);

		/*
		 * If the operation was successful, then do
		 * the required updates.
		 */
		if (alter)
			do_smart_update(sma, sops, nsops, 1, &wake_q);
		else
			set_semotime(sma, sops);

		sem_unlock(sma, locknum);
		rcu_read_unlock();
		wake_up_q(&wake_q);

		goto out_free;
	}
	if (error < 0) /* non-blocking error path */
		goto out_unlock_free;

	/*
	 * We need to sleep on this operation, so we put the current
	 * task into the pending queue and go to sleep.
	 */
	if (nsops == 1) {
		struct sem *curr;
		int idx = array_index_nospec(sops->sem_num, sma->sem_nsems);
		curr = &sma->sems[idx];

		if (alter) {
			if (sma->complex_count) {
				list_add_tail(&queue.list,
						&sma->pending_alter);
			} else {

				list_add_tail(&queue.list,
						&curr->pending_alter);
			}
		} else {
			list_add_tail(&queue.list, &curr->pending_const);
		}
	} else {
		if (!sma->complex_count)
			merge_queues(sma);

		if (alter)
			list_add_tail(&queue.list, &sma->pending_alter);
		else
			list_add_tail(&queue.list, &sma->pending_const);

		sma->complex_count++;
	}

	do {
		WRITE_ONCE(queue.status, -EINTR);
		queue.sleeper = current;

		__set_current_state(TASK_INTERRUPTIBLE);
		sem_unlock(sma, locknum);
		rcu_read_unlock();

		if (timeout)
			jiffies_left = schedule_timeout(jiffies_left);
		else
			schedule();

		/*
		 * fastpath: the semop has completed, either successfully or
		 * not, from the syscall pov, is quite irrelevant to us at this
		 * point; we're done.
		 *
		 * We _do_ care, nonetheless, about being awoken by a signal or
		 * spuriously.  The queue.status is checked again in the
		 * slowpath (aka after taking sem_lock), such that we can detect
		 * scenarios where we were awakened externally, during the
		 * window between wake_q_add() and wake_up_q().
		 */
		error = READ_ONCE(queue.status);
		if (error != -EINTR) {
			/*
			 * User space could assume that semop() is a memory
			 * barrier: Without the mb(), the cpu could
			 * speculatively read in userspace stale data that was
			 * overwritten by the previous owner of the semaphore.
			 */
			smp_mb();
			goto out_free;
		}

		rcu_read_lock();
		locknum = sem_lock(sma, sops, nsops);

		if (!ipc_valid_object(&sma->sem_perm))
			goto out_unlock_free;

		error = READ_ONCE(queue.status);

		/*
		 * If queue.status != -EINTR we are woken up by another process.
		 * Leave without unlink_queue(), but with sem_unlock().
		 */
		if (error != -EINTR)
			goto out_unlock_free;

		/*
		 * If an interrupt occurred we have to clean up the queue.
		 */
		if (timeout && jiffies_left == 0)
			error = -EAGAIN;
	} while (error == -EINTR && !signal_pending(current)); /* spurious */

	unlink_queue(sma, &queue);

out_unlock_free:
	sem_unlock(sma, locknum);
	rcu_read_unlock();
out_free:
	if (sops != fast_sops)
		kvfree(sops);
	return error;
}

static inline struct sem_array *sem_obtain_object_check(struct ipc_namespace *ns,
							int id)
{
	struct kern_ipc_perm *ipcp = ipc_obtain_object_check(&sem_ids(ns), id);

	if (IS_ERR(ipcp))
		return ERR_CAST(ipcp);

	return container_of(ipcp, struct sem_array, sem_perm);
}

/**
 * ipcperms - check ipc permissions
 * @ns: ipc namespace
 * @ipcp: ipc permission set
 * @flag: desired permission set
 *
 * Check user, group, other permissions for access
 * to ipc resources. return 0 if allowed
 *
 * @flag will most probably be 0 or ``S_...UGO`` from <linux/stat.h>
 */
int ipcperms(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp, short flag)
{
	kuid_t euid = current_euid();
	int requested_mode, granted_mode;

	audit_ipc_obj(ipcp);
	requested_mode = (flag >> 6) | (flag >> 3) | flag;
	granted_mode = ipcp->mode;
	if (uid_eq(euid, ipcp->cuid) ||
	    uid_eq(euid, ipcp->uid))
		granted_mode >>= 6;
	else if (in_group_p(ipcp->cgid) || in_group_p(ipcp->gid))
		granted_mode >>= 3;
	/* is there some bit set in requested_mode but not in granted_mode? */
	if ((requested_mode & ~granted_mode & 0007) &&
	    !ns_capable(ns->user_ns, CAP_IPC_OWNER))
		return -1;

	return security_ipc_permission(ipcp, flag);
}