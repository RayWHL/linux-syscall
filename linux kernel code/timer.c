/**
 * struct k_itimer - POSIX.1b interval timer structure.
 * @list:		List head for binding the timer to signals->posix_timers
 * @t_hash:		Entry in the posix timer hash table
 * @it_lock:		Lock protecting the timer
 * @kclock:		Pointer to the k_clock struct handling this timer
 * @it_clock:		The posix timer clock id
 * @it_id:		The posix timer id for identifying the timer
 * @it_active:		Marker that timer is active
 * @it_overrun:		The overrun counter for pending signals 等待信号的overrun计时器
 * @it_overrun_last:	The overrun at the time of the last delivered  最后依次发送信号后的
 * @it_requeue_pending:	Indicator that timer waits for being requeued on
 *			signal delivery
 * @it_sigev_notify:	The notify word of sigevent struct for signal delivery  信号传递sigevent结构的notify
 * @it_interval:	The interval for periodic timers 周期定时器的间隔？
 * @it_signal:		Pointer to the creators signal struct
 * @it_pid:		The pid of the process/task targeted by the signal
 * @it_process:		The task to wakeup on clock_nanosleep (CPU timers)
 * @sigq:		Pointer to preallocated sigqueue
 * @it:			Union representing the various posix timer type
 *			internals. Also used for rcu freeing the timer.
 */
struct k_itimer {
	struct list_head	list;
	struct hlist_node	t_hash;
	spinlock_t		it_lock;
	const struct k_clock	*kclock;
	clockid_t		it_clock;
	timer_t			it_id;
	int			it_active;
	s64			it_overrun;
	s64			it_overrun_last;
	int			it_requeue_pending;
	int			it_sigev_notify;
	ktime_t			it_interval;
	struct signal_struct	*it_signal;
	union {
		struct pid		*it_pid;
		struct task_struct	*it_process;
	};
	struct sigqueue		*sigq;
	union {
		struct {
			struct hrtimer	timer;
		} real;
		struct cpu_timer_list	cpu;
		struct {
			struct alarm	alarmtimer;
		} alarm;
		struct rcu_head		rcu;
	} it;
};

//