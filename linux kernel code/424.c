typedef struct siginfo {
	union {
		__SIGINFO;
		int _si_pad[SI_MAX_SIZE/sizeof(int)];
	};
} __ARCH_SI_ATTRIBUTES siginfo_t;

#define __SIGINFO 			\
struct {				\
	int si_signo;			\
	int si_errno;			\
	int si_code;			\
	union __sifields _sifields;	\
}

/**
 * sys_pidfd_send_signal - send a signal to a process through a task file
 *                          descriptor
 * @pidfd:  the file descriptor of the process
 * @sig:    signal to be sent
 * @info:   the signal info
 * @flags:  future flags to be passed
 *
 * The syscall currently only signals via PIDTYPE_PID which covers
 * kill(<positive-pid>, <signal>. It does not signal threads or process
 * groups.
 * In order to extend the syscall to threads and process groups the @flags
 * argument should be used. In essence, the @flags argument will determine
 * what is signaled and not the file descriptor itself. Put in other words,
 * grouping is a property of the flags argument not a property of the file
 * descriptor.
 *
 * Return: 0 on success, negative errno on failure
 */
SYSCALL_DEFINE4(pidfd_send_signal, int, pidfd, int, sig,
		siginfo_t __user *, info, unsigned int, flags)
{
	int ret;
	struct fd f;
	struct pid *pid;
	kernel_siginfo_t kinfo;

	/* Enforce flags be set to 0 until we add an extension. */
	if (flags)
		return -EINVAL;

	f = fdget(pidfd);       //通过current->files获得文件fd结构
	if (!f.file)
		return -EBADF;

	/* Is this a pidfd? */                     //inode是proc_inode的一个成员
	pid = tgid_pidfd_to_pid(f.file);        //通过获取的文件的inode获得对应proc_inode结构，并取pid
	if (IS_ERR(pid)) {
		ret = PTR_ERR(pid);
		goto err;
	}

	ret = -EINVAL;
	if (!access_pidfd_pidns(pid))       //验证信号发送者接受者是否在同一namespace，或者发送者是接收者的祖父namespace
		goto err;

	if (info) {
		ret = copy_siginfo_from_user_any(&kinfo, info); //将info从用户空间拷贝到内核空间
		if (unlikely(ret))
			goto err;

		ret = -EINVAL;
		if (unlikely(sig != kinfo.si_signo))
			goto err;

		/* Only allow sending arbitrary signals to yourself. */
		ret = -EPERM;
		if ((task_pid(current) != pid) &&
		    (kinfo.si_code >= 0 || kinfo.si_code == SI_TKILL))
			goto err;
	} else {
		prepare_kill_siginfo(sig, &kinfo);      //初始化一个siginfo_t
	}

	ret = kill_pid_info(sig, &kinfo, pid);      //发送信号，将信号送入目的pid的task_struct

err:
	fdput(f);
	return ret;
}

int kill_pid_info(int sig, struct kernel_siginfo *info, struct pid *pid)
{
	int error = -ESRCH;
	struct task_struct *p;

	for (;;) {
		rcu_read_lock();
		p = pid_task(pid, PIDTYPE_PID);
		if (p)
			error = group_send_sig_info(sig, info, p, PIDTYPE_TGID);
		rcu_read_unlock();
		if (likely(!p || error != -ESRCH))
			return error;

		/*
		 * The task was unhashed in between, try again.  If it
		 * is dead, pid_task() will return NULL, if we race with
		 * de_thread() it will find the new leader.
		 */
	}
}


static inline struct fd fdget(unsigned int fd)
{
	return __to_fd(__fdget(fd));
}
static inline struct fd __to_fd(unsigned long v)
{
	return (struct fd){(struct file *)(v & ~3),v & 3};
}

unsigned long __fdget(unsigned int fd)
{
	return __fget_light(fd, FMODE_PATH);
}
/*
 * Lightweight file lookup - no refcnt increment if fd table isn't shared.
 *
 * You can use this instead of fget if you satisfy all of the following
 * conditions:
 * 1) You must call fput_light before exiting the syscall and returning control
 *    to userspace (i.e. you cannot remember the returned struct file * after
 *    returning to userspace).
 * 2) You must not call filp_close on the returned struct file * in between
 *    calls to fget_light and fput_light.
 * 3) You must not clone the current task in between the calls to fget_light
 *    and fput_light.
 *
 * The fput_needed flag returned by fget_light should be passed to the
 * corresponding fput_light.
 */
static unsigned long __fget_light(unsigned int fd, fmode_t mask)
{
	struct files_struct *files = current->files;
	struct file *file;

	if (atomic_read(&files->count) == 1) {
		file = __fcheck_files(files, fd);
		if (!file || unlikely(file->f_mode & mask))
			return 0;
		return (unsigned long)file;
	} else {
		file = __fget(fd, mask, 1);
		if (!file)
			return 0;
		return FDPUT_FPUT | (unsigned long)file;
	}
}

/*
 * The caller must ensure that fd table isn't shared or hold rcu or file lock
 */
static inline struct file *__fcheck_files(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = rcu_dereference_raw(files->fdt);

	if (fd < fdt->max_fds) {
		fd = array_index_nospec(fd, fdt->max_fds);
		return rcu_dereference_raw(fdt->fd[fd]);
	}
	return NULL;
}

struct pid *tgid_pidfd_to_pid(const struct file *file)
{
	if (!d_is_dir(file->f_path.dentry) ||
	    (file->f_op != &proc_tgid_base_operations))
		return ERR_PTR(-EBADF);     //

	return proc_pid(file_inode(file));
}
