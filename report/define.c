#ifdef __SYSCALL_COMPAT
#define __SC_COMP(_nr, _sys, _comp) __SYSCALL(_nr, _comp)
#define __SC_COMP_3264(_nr, _32, _64, _comp) __SYSCALL(_nr, _comp)
#else
#define __SC_COMP(_nr, _sys, _comp) __SYSCALL(_nr, _sys)
#define __SC_COMP_3264(_nr, _32, _64, _comp) __SC_3264(_nr, _32, _64)
#endif

#define CLOCKFD_MASK		(CPUCLOCK_PERTHREAD_MASK|CPUCLOCK_CLOCK_MASK)
#define CPUCLOCK_PERTHREAD_MASK	4
#define CPUCLOCK_CLOCK_MASK	3
#define CLOCKFD			CPUCLOCK_MAX


//结构体 k_clock
struct k_clock {
	int	(*clock_getres)(const clockid_t which_clock,
				struct timespec64 *tp);
	int	(*clock_set)(const clockid_t which_clock,
			     const struct timespec64 *tp);
	int	(*clock_get)(const clockid_t which_clock,
			     struct timespec64 *tp);
	int	(*clock_adj)(const clockid_t which_clock, struct __kernel_timex *tx);
	int	(*timer_create)(struct k_itimer *timer);
	int	(*nsleep)(const clockid_t which_clock, int flags,
			  const struct timespec64 *);
	int	(*timer_set)(struct k_itimer *timr, int flags,
			     struct itimerspec64 *new_setting,
			     struct itimerspec64 *old_setting);
	int	(*timer_del)(struct k_itimer *timr);
	void	(*timer_get)(struct k_itimer *timr,
			     struct itimerspec64 *cur_setting);
	void	(*timer_rearm)(struct k_itimer *timr);
	s64	(*timer_forward)(struct k_itimer *timr, ktime_t now);
	ktime_t	(*timer_remaining)(struct k_itimer *timr, ktime_t now);
	int	(*timer_try_to_cancel)(struct k_itimer *timr);
	void	(*timer_arm)(struct k_itimer *timr, ktime_t expires,
			     bool absolute, bool sigev_none);
};

const struct k_clock clock_posix_dynamic = {
	.clock_getres	= pc_clock_getres,
	.clock_set	= pc_clock_settime,
	.clock_get	= pc_clock_gettime,
	.clock_adj	= pc_clock_adjtime,
};
static const struct k_clock * const posix_clocks[] = {
	[CLOCK_REALTIME]		= &clock_realtime,
	[CLOCK_MONOTONIC]		= &clock_monotonic,
	[CLOCK_PROCESS_CPUTIME_ID]	= &clock_process,
	[CLOCK_THREAD_CPUTIME_ID]	= &clock_thread,
	[CLOCK_MONOTONIC_RAW]		= &clock_monotonic_raw,
	[CLOCK_REALTIME_COARSE]		= &clock_realtime_coarse,
	[CLOCK_MONOTONIC_COARSE]	= &clock_monotonic_coarse,
	[CLOCK_BOOTTIME]		= &clock_boottime,
	[CLOCK_REALTIME_ALARM]		= &alarm_clock,
	[CLOCK_BOOTTIME_ALARM]		= &alarm_clock,
	[CLOCK_TAI]			= &clock_tai,
};

const struct k_clock clock_posix_cpu = {
	.clock_getres	= posix_cpu_clock_getres,
	.clock_set	= posix_cpu_clock_set,
	.clock_get	= posix_cpu_clock_get,
	.timer_create	= posix_cpu_timer_create,
	.nsleep		= posix_cpu_nsleep,
	.timer_set	= posix_cpu_timer_set,
	.timer_del	= posix_cpu_timer_del,
	.timer_get	= posix_cpu_timer_get,
	.timer_rearm	= posix_cpu_timer_rearm,
};

static const struct k_clock clock_realtime = {
	.clock_getres		= posix_get_hrtimer_res,
	.clock_get		= posix_clock_realtime_get,
	.clock_set		= posix_clock_realtime_set,
	.clock_adj		= posix_clock_realtime_adj,
	.nsleep			= common_nsleep,
	.timer_create		= common_timer_create,
	.timer_set		= common_timer_set,
	.timer_get		= common_timer_get,
	.timer_del		= common_timer_del,
	.timer_rearm		= common_hrtimer_rearm,
	.timer_forward		= common_hrtimer_forward,
	.timer_remaining	= common_hrtimer_remaining,
	.timer_try_to_cancel	= common_hrtimer_try_to_cancel,
	.timer_arm		= common_hrtimer_arm,
};

static const struct k_clock clock_monotonic = {
	.clock_getres		= posix_get_hrtimer_res,
	.clock_get		= posix_ktime_get_ts,
	.nsleep			= common_nsleep,
	.timer_create		= common_timer_create,
	.timer_set		= common_timer_set,
	.timer_get		= common_timer_get,
	.timer_del		= common_timer_del,
	.timer_rearm		= common_hrtimer_rearm,
	.timer_forward		= common_hrtimer_forward,
	.timer_remaining	= common_hrtimer_remaining,
	.timer_try_to_cancel	= common_hrtimer_try_to_cancel,
	.timer_arm		= common_hrtimer_arm,
};

const struct k_clock clock_process = {
	.clock_getres	= process_cpu_clock_getres,
	.clock_get	= process_cpu_clock_get,
	.timer_create	= process_cpu_timer_create,
	.nsleep		= process_cpu_nsleep,
};

const struct k_clock clock_thread = {
	.clock_getres	= thread_cpu_clock_getres,
	.clock_get	= thread_cpu_clock_get,
	.timer_create	= thread_cpu_timer_create,
};

//函数 clockid_to_kclock
static const struct k_clock *clockid_to_kclock(const clockid_t id)
{
	clockid_t idx = id;

	if (id < 0) {
		return (id & CLOCKFD_MASK) == CLOCKFD ?
			&clock_posix_dynamic : &clock_posix_cpu;
	}

	if (id >= ARRAY_SIZE(posix_clocks))
		return NULL;

	return posix_clocks[array_index_nospec(idx, ARRAY_SIZE(posix_clocks))];
}

//函数 get_timespec64
int get_timespec64(struct timespec64 *ts,
		   const struct __kernel_timespec __user *uts)
{
	struct __kernel_timespec kts;
	int ret;

	ret = copy_from_user(&kts, uts, sizeof(kts));
	if (ret)
		return -EFAULT;

	ts->tv_sec = kts.tv_sec;

	/* Zero out the padding for 32 bit systems or in compat mode */
	if (IS_ENABLED(CONFIG_64BIT_TIME) && in_compat_syscall())
		kts.tv_nsec &= 0xFFFFFFFFUL;

	ts->tv_nsec = kts.tv_nsec;

	return 0;
}

//realtime 的 clock_set函数
static int posix_clock_realtime_set(const clockid_t which_clock,
				    const struct timespec64 *tp)
{
	return do_sys_settimeofday64(tp, NULL);
}

int do_sys_settimeofday64(const struct timespec64 *tv, const struct timezone *tz)
{
	static int firsttime = 1;
	int error = 0;

	if (tv && !timespec64_valid_settod(tv))
		return -EINVAL;

	error = security_settime64(tv, tz);
	if (error)
		return error;

	if (tz) {
		/* Verify we're witin the +-15 hrs range */
		if (tz->tz_minuteswest > 15*60 || tz->tz_minuteswest < -15*60)
			return -EINVAL;

		sys_tz = *tz;
		update_vsyscall_tz();
		if (firsttime) {
			firsttime = 0;
			if (!tv)
				timekeeping_warp_clock();
		}
	}
	if (tv)
		return do_settimeofday64(tv);
	return 0;
}

int do_settimeofday64(const struct timespec64 *ts)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	struct timespec64 ts_delta, xt;
	unsigned long flags;
	int ret = 0;

	if (!timespec64_valid_settod(ts))
		return -EINVAL;

	raw_spin_lock_irqsave(&timekeeper_lock, flags);
	write_seqcount_begin(&tk_core.seq);

	timekeeping_forward_now(tk);

	xt = tk_xtime(tk);
	ts_delta.tv_sec = ts->tv_sec - xt.tv_sec;
	ts_delta.tv_nsec = ts->tv_nsec - xt.tv_nsec;

	if (timespec64_compare(&tk->wall_to_monotonic, &ts_delta) > 0) {
		ret = -EINVAL;
		goto out;
	}

	tk_set_wall_to_mono(tk, timespec64_sub(tk->wall_to_monotonic, ts_delta));

	tk_set_xtime(tk, ts);
out:
	timekeeping_update(tk, TK_CLEAR_NTP | TK_MIRROR | TK_CLOCK_WAS_SET);

	write_seqcount_end(&tk_core.seq);
	raw_spin_unlock_irqrestore(&timekeeper_lock, flags);

	/* signal hrtimers about time change */
	clock_was_set();

	return ret;
}

struct __kernel_timex {
	unsigned int modes;	/* mode selector */
	int :32;            /* pad */
	long long offset;	/* time offset (usec) */
	long long freq;	/* frequency offset (scaled ppm) */
	long long maxerror;/* maximum error (usec) */
	long long esterror;/* estimated error (usec) */
	int status;		/* clock command/status */
	int :32;            /* pad */
	long long constant;/* pll time constant */
	long long precision;/* clock precision (usec) (read only) */
	long long tolerance;/* clock frequency tolerance (ppm)
				   * (read only)
				   */
	struct __kernel_timex_timeval time;	/* (read only, except for ADJ_SETOFFSET) */
	long long tick;	/* (modified) usecs between clock ticks */

	long long ppsfreq;/* pps frequency (scaled ppm) (ro) */
	long long jitter; /* pps jitter (us) (ro) */
	int shift;              /* interval duration (s) (shift) (ro) */
	int :32;            /* pad */
	long long stabil;            /* pps stability (scaled ppm) (ro) */
	long long jitcnt; /* jitter limit exceeded (ro) */
	long long calcnt; /* calibration intervals (ro) */
	long long errcnt; /* calibration errors (ro) */
	long long stbcnt; /* stability limit exceeded (ro) */

	int tai;		/* TAI offset (ro) */

	int  :32; int  :32; int  :32; int  :32;
	int  :32; int  :32; int  :32; int  :32;
	int  :32; int  :32; int  :32;
};


//realtime 的 adjtime函数
/**
 * do_adjtimex() - Accessor function to NTP __do_adjtimex function
 */
int do_adjtimex(struct __kernel_timex *txc)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	unsigned long flags;
	struct timespec64 ts;
	s32 orig_tai, tai;
	int ret;

	/* Validate the data before disabling interrupts */
	ret = timekeeping_validate_timex(txc);
	if (ret)
		return ret;

	if (txc->modes & ADJ_SETOFFSET) {  /* add 'time' to current time */
		struct timespec64 delta;
		delta.tv_sec  = txc->time.tv_sec;
		delta.tv_nsec = txc->time.tv_usec;
		if (!(txc->modes & ADJ_NANO))	/* select nanosecond resolution */
			delta.tv_nsec *= 1000;
		ret = timekeeping_inject_offset(&delta);  //加或减偏移值 修改timekeeper 使用到锁
		if (ret)
			return ret;
	}

	ktime_get_real_ts64(&ts);	//Returns the time of day in a timespec64.

	raw_spin_lock_irqsave(&timekeeper_lock, flags);
	write_seqcount_begin(&tk_core.seq);

	orig_tai = tai = tk->tai_offset;
	ret = __do_adjtimex(txc, &ts, &tai);

	if (tai != orig_tai) {
		__timekeeping_set_tai_offset(tk, tai);
		timekeeping_update(tk, TK_MIRROR | TK_CLOCK_WAS_SET);
	}
	tk_update_leap_state(tk);

	write_seqcount_end(&tk_core.seq);
	raw_spin_unlock_irqrestore(&timekeeper_lock, flags);

	/* Update the multiplier immediately if frequency was set directly */
	if (txc->modes & (ADJ_FREQUENCY | ADJ_TICK))
		timekeeping_advance(TK_ADV_FREQ);

	if (tai != orig_tai)
		clock_was_set();

	ntp_notify_cmos_timer();

	return ret;
}

//realtime nsleep函数
long hrtimer_nanosleep(const struct timespec64 *rqtp,
		       const enum hrtimer_mode mode, const clockid_t clockid)
{
	struct restart_block *restart;
	struct hrtimer_sleeper t;
	int ret = 0;
	u64 slack;

	slack = current->timer_slack_ns;
	if (dl_task(current) || rt_task(current))
		slack = 0;

	hrtimer_init_on_stack(&t.timer, clockid, mode);
	hrtimer_set_expires_range_ns(&t.timer, timespec64_to_ktime(*rqtp), slack);
	ret = do_nanosleep(&t, mode);
	if (ret != -ERESTART_RESTARTBLOCK)
		goto out;

	/* Absolute timers do not update the rmtp value and restart: */
	if (mode == HRTIMER_MODE_ABS) {
		ret = -ERESTARTNOHAND;
		goto out;
	}

	restart = &current->restart_block;
	restart->fn = hrtimer_nanosleep_restart;
	restart->nanosleep.clockid = t.timer.base->clockid;
	restart->nanosleep.expires = hrtimer_get_expires_tv64(&t.timer);
out:
	destroy_hrtimer_on_stack(&t.timer);
	return ret;
}