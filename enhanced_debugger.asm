section .rodata

sys_read db 'SYS_READ', 0xA, 0
sys_write db 'SYS_WRITE', 0xA, 0
sys_open db 'SYS_OPEN', 0xA, 0
sys_close db 'SYS_CLOSE', 0xA, 0
sys_stat db 'SYS_STAT', 0xA, 0
sys_fstat db 'SYS_FSTAT', 0xA, 0
sys_lstat db 'SYS_LSTAT', 0xA, 0
sys_poll db 'SYS_POLL', 0xA, 0
sys_lseek db 'SYS_LSEEK', 0xA, 0
sys_mmap db 'SYS_MMAP', 0xA, 0
sys_mprotect db 'SYS_MPROTECT', 0xA, 0
sys_munmap db 'SYS_MUNMAP', 0xA, 0
sys_brk db 'SYS_BRK', 0xA, 0
sys_rt_sigaction db 'SYS_RT_SIGACTION', 0xA, 0
sys_rt_sigprocmask db 'SYS_RT_SIGPROCMASK', 0xA, 0
sys_rt_sigreturn db 'SYS_RT_SIGRETURN', 0xA, 0
sys_ioctl db 'SYS_IOCTL', 0xA, 0
sys_pread64 db 'SYS_PREAD64', 0xA, 0
sys_pwrite64 db 'SYS_PWRITE64', 0xA, 0
sys_readv db 'SYS_READV', 0xA, 0
sys_writev db 'SYS_WRITEV', 0xA, 0
sys_access db 'SYS_ACCESS', 0xA, 0
sys_pipe db 'SYS_PIPE', 0xA, 0
sys_select db 'SYS_SELECT', 0xA, 0
sys_sched_yield db 'SYS_SCHED_YIELD', 0xA, 0
sys_mremap db 'SYS_MREMAP', 0xA, 0
sys_msync db 'SYS_MSYNC', 0xA, 0
sys_mincore db 'SYS_MINCORE', 0xA, 0
sys_madvise db 'SYS_MADVISE', 0xA, 0
sys_shmget db 'SYS_SHMGET', 0xA, 0
sys_shmat db 'SYS_SHMAT', 0xA, 0
sys_shmctl db 'SYS_SHMCTL', 0xA, 0
sys_dup db 'SYS_DUP', 0xA, 0
sys_dup2 db 'SYS_DUP2', 0xA, 0
sys_pause db 'SYS_PAUSE', 0xA, 0
sys_nanosleep db 'SYS_NANOSLEEP', 0xA, 0
sys_getitimer db 'SYS_GETITIMER', 0xA, 0
sys_alarm db 'SYS_ALARM', 0xA, 0
sys_setitimer db 'SYS_SETITIMER', 0xA, 0
sys_getpid db 'SYS_GETPID', 0xA, 0
sys_sendfile db 'SYS_SENDFILE', 0xA, 0
sys_socket db 'SYS_SOCKET', 0xA, 0
sys_connect db 'SYS_CONNECT', 0xA, 0
sys_accept db 'SYS_ACCEPT', 0xA, 0
sys_sendto db 'SYS_SENDTO', 0xA, 0
sys_recvfrom db 'SYS_RECVFROM', 0xA, 0
sys_sendmsg db 'SYS_SENDMSG', 0xA, 0
sys_recvmsg db 'SYS_RECVMSG', 0xA, 0
sys_shutdown db 'SYS_SHUTDOWN', 0xA, 0
sys_bind db 'SYS_BIND', 0xA, 0
sys_listen db 'SYS_LISTEN', 0xA, 0
sys_getsockname db 'SYS_GETSOCKNAME', 0xA, 0
sys_getpeername db 'SYS_GETPEERNAME', 0xA, 0
sys_socketpair db 'SYS_SOCKETPAIR', 0xA, 0
sys_setsockopt db 'SYS_SETSOCKOPT', 0xA, 0
sys_getsockopt db 'SYS_GETSOCKOPT', 0xA, 0
sys_clone db 'SYS_CLONE', 0xA, 0
sys_fork db 'SYS_FORK', 0xA, 0
sys_vfork db 'SYS_VFORK', 0xA, 0
sys_execve db 'SYS_EXECVE', 0xA, 0
sys_exit db 'SYS_EXIT', 0xA, 0
sys_wait4 db 'SYS_WAIT4', 0xA, 0
sys_kill db 'SYS_KILL', 0xA, 0
sys_uname db 'SYS_UNAME', 0xA, 0
sys_semget db 'SYS_SEMGET', 0xA, 0
sys_semop db 'SYS_SEMOP', 0xA, 0
sys_semctl db 'SYS_SEMCTL', 0xA, 0
sys_shmdt db 'SYS_SHMDT', 0xA, 0
sys_msgget db 'SYS_MSGGET', 0xA, 0
sys_msgsnd db 'SYS_MSGSND', 0xA, 0
sys_msgrcv db 'SYS_MSGRCV', 0xA, 0
sys_msgctl db 'SYS_MSGCTL', 0xA, 0
sys_fcntl db 'SYS_FCNTL', 0xA, 0
sys_flock db 'SYS_FLOCK', 0xA, 0
sys_fsync db 'SYS_FSYNC', 0xA, 0
sys_fdatasync db 'SYS_FDATASYNC', 0xA, 0
sys_truncate db 'SYS_TRUNCATE', 0xA, 0
sys_ftruncate db 'SYS_FTRUNCATE', 0xA, 0
sys_getdents db 'SYS_GETDENTS', 0xA, 0
sys_getcwd db 'SYS_GETCWD', 0xA, 0
sys_chdir db 'SYS_CHDIR', 0xA, 0
sys_fchdir db 'SYS_FCHDIR', 0xA, 0
sys_rename db 'SYS_RENAME', 0xA, 0
sys_mkdir db 'SYS_MKDIR', 0xA, 0
sys_rmdir db 'SYS_RMDIR', 0xA, 0
sys_creat db 'SYS_CREAT', 0xA, 0
sys_link db 'SYS_LINK', 0xA, 0
sys_unlink db 'SYS_UNLINK', 0xA, 0
sys_symlink db 'SYS_SYMLINK', 0xA, 0
sys_readlink db 'SYS_READLINK', 0xA, 0
sys_chmod db 'SYS_CHMOD', 0xA, 0
sys_fchmod db 'SYS_FCHMOD', 0xA, 0
sys_chown db 'SYS_CHOWN', 0xA, 0
sys_fchown db 'SYS_FCHOWN', 0xA, 0
sys_lchown db 'SYS_LCHOWN', 0xA, 0
sys_umask db 'SYS_UMASK', 0xA, 0
sys_gettimeofday db 'SYS_GETTIMEOFDAY', 0xA, 0
sys_getrlimit db 'SYS_GETRLIMIT', 0xA, 0
sys_getrusage db 'SYS_GETRUSAGE', 0xA, 0
sys_sysinfo db 'SYS_SYSINFO', 0xA, 0
sys_times db 'SYS_TIMES', 0xA, 0
sys_ptrace db 'SYS_PTRACE', 0xA, 0
sys_getuid db 'SYS_GETUID', 0xA, 0
sys_syslog db 'SYS_SYSLOG', 0xA, 0
sys_getgid db 'SYS_GETGID', 0xA, 0
sys_setuid db 'SYS_SETUID', 0xA, 0
sys_setgid db 'SYS_SETGID', 0xA, 0
sys_geteuid db 'SYS_GETEUID', 0xA, 0
sys_getegid db 'SYS_GETEGID', 0xA, 0
sys_setpgid db 'SYS_SETPGID', 0xA, 0
sys_getppid db 'SYS_GETPPID', 0xA, 0
sys_getpgrp db 'SYS_GETPGRP', 0xA, 0
sys_setsid db 'SYS_SETSID', 0xA, 0
sys_setreuid db 'SYS_SETREUID', 0xA, 0
sys_setregid db 'SYS_SETREGID', 0xA, 0
sys_getgroups db 'SYS_GETGROUPS', 0xA, 0
sys_setgroups db 'SYS_SETGROUPS', 0xA, 0
sys_setresuid db 'SYS_SETRESUID', 0xA, 0
sys_getresuid db 'SYS_GETRESUID', 0xA, 0
sys_setresgid db 'SYS_SETRESGID', 0xA, 0
sys_getresgid db 'SYS_GETRESGID', 0xA, 0
sys_getpgid db 'SYS_GETPGID', 0xA, 0
sys_setfsuid db 'SYS_SETFSUID', 0xA, 0
sys_setfsgid db 'SYS_SETFSGID', 0xA, 0
sys_getsid db 'SYS_GETSID', 0xA, 0
sys_capget db 'SYS_CAPGET', 0xA, 0
sys_capset db 'SYS_CAPSET', 0xA, 0
sys_rt_sigpending db 'SYS_RT_SIGPENDING', 0xA, 0
sys_rt_sigtimedwait db 'SYS_RT_SIGTIMEDWAIT', 0xA, 0
sys_rt_sigqueueinfo db 'SYS_RT_SIGQUEUEINFO', 0xA, 0
sys_rt_sigsuspend db 'SYS_RT_SIGSUSPEND', 0xA, 0
sys_sigaltstack db 'SYS_SIGALTSTACK', 0xA, 0
sys_utime db 'SYS_UTIME', 0xA, 0
sys_mknod db 'SYS_MKNOD', 0xA, 0
sys_uselib db 'SYS_USELIB', 0xA, 0
sys_personality db 'SYS_PERSONALITY', 0xA, 0
sys_ustat db 'SYS_USTAT', 0xA, 0
sys_statfs db 'SYS_STATFS', 0xA, 0
sys_fstatfs db 'SYS_FSTATFS', 0xA, 0
sys_sysfs db 'SYS_SYSFS', 0xA, 0
sys_getpriority db 'SYS_GETPRIORITY', 0xA, 0
sys_setpriority db 'SYS_SETPRIORITY', 0xA, 0
sys_sched_setparam db 'SYS_SCHED_SETPARAM', 0xA, 0
sys_sched_getparam db 'SYS_SCHED_GETPARAM', 0xA, 0
sys_sched_setscheduler db 'SYS_SCHED_SETSCHEDULER', 0xA, 0
sys_sched_getscheduler db 'SYS_SCHED_GETSCHEDULER', 0xA, 0
sys_sched_get_priority_max db 'SYS_SCHED_GET_PRIORITY_MAX', 0xA, 0
sys_sched_get_priority_min db 'SYS_SCHED_GET_PRIORITY_MIN', 0xA, 0
sys_sched_rr_get_interval db 'SYS_SCHED_RR_GET_INTERVAL', 0xA, 0
sys_mlock db 'SYS_MLOCK', 0xA, 0
sys_munlock db 'SYS_MUNLOCK', 0xA, 0
sys_mlockall db 'SYS_MLOCKALL', 0xA, 0
sys_munlockall db 'SYS_MUNLOCKALL', 0xA, 0
sys_vhangup db 'SYS_VHANGUP', 0xA, 0
sys_modify_ldt db 'SYS_MODIFY_LDT', 0xA, 0
sys_pivot_root db 'SYS_PIVOT_ROOT', 0xA, 0
sys__sysctl db 'SYS__SYSCTL', 0xA, 0
sys_prctl db 'SYS_PRCTL', 0xA, 0
sys_arch_prctl db 'SYS_ARCH_PRCTL', 0xA, 0
sys_adjtimex db 'SYS_ADJTIMEX', 0xA, 0
sys_setrlimit db 'SYS_SETRLIMIT', 0xA, 0
sys_chroot db 'SYS_CHROOT', 0xA, 0
sys_sync db 'SYS_SYNC', 0xA, 0
sys_acct db 'SYS_ACCT', 0xA, 0
sys_settimeofday db 'SYS_SETTIMEOFDAY', 0xA, 0
sys_mount db 'SYS_MOUNT', 0xA, 0
sys_umount2 db 'SYS_UMOUNT2', 0xA, 0
sys_swapon db 'SYS_SWAPON', 0xA, 0
sys_swapoff db 'SYS_SWAPOFF', 0xA, 0
sys_reboot db 'SYS_REBOOT', 0xA, 0
sys_sethostname db 'SYS_SETHOSTNAME', 0xA, 0
sys_setdomainname db 'SYS_SETDOMAINNAME', 0xA, 0
sys_iopl db 'SYS_IOPL', 0xA, 0
sys_ioperm db 'SYS_IOPERM', 0xA, 0
sys_create_module db 'SYS_CREATE_MODULE', 0xA, 0
sys_init_module db 'SYS_INIT_MODULE', 0xA, 0
sys_delete_module db 'SYS_DELETE_MODULE', 0xA, 0
sys_get_kernel_syms db 'SYS_GET_KERNEL_SYMS', 0xA, 0
sys_query_module db 'SYS_QUERY_MODULE', 0xA, 0
sys_quotactl db 'SYS_QUOTACTL', 0xA, 0
sys_nfsservctl db 'SYS_NFSSERVCTL', 0xA, 0
sys_getpmsg db 'SYS_GETPMSG', 0xA, 0
sys_putpmsg db 'SYS_PUTPMSG', 0xA, 0
sys_afs_syscall db 'SYS_AFS_SYSCALL', 0xA, 0
sys_tuxcall db 'SYS_TUXCALL', 0xA, 0
sys_security db 'SYS_SECURITY', 0xA, 0
sys_gettid db 'SYS_GETTID', 0xA, 0
sys_readahead db 'SYS_READAHEAD', 0xA, 0
sys_setxattr db 'SYS_SETXATTR', 0xA, 0
sys_lsetxattr db 'SYS_LSETXATTR', 0xA, 0
sys_fsetxattr db 'SYS_FSETXATTR', 0xA, 0
sys_getxattr db 'SYS_GETXATTR', 0xA, 0
sys_lgetxattr db 'SYS_LGETXATTR', 0xA, 0
sys_fgetxattr db 'SYS_FGETXATTR', 0xA, 0
sys_listxattr db 'SYS_LISTXATTR', 0xA, 0
sys_llistxattr db 'SYS_LLISTXATTR', 0xA, 0
sys_flistxattr db 'SYS_FLISTXATTR', 0xA, 0
sys_removexattr db 'SYS_REMOVEXATTR', 0xA, 0
sys_lremovexattr db 'SYS_LREMOVEXATTR', 0xA, 0
sys_fremovexattr db 'SYS_FREMOVEXATTR', 0xA, 0
sys_tkill db 'SYS_TKILL', 0xA, 0
sys_time db 'SYS_TIME', 0xA, 0
sys_futex db 'SYS_FUTEX', 0xA, 0
sys_sched_setaffinity db 'SYS_SCHED_SETAFFINITY', 0xA, 0
sys_sched_getaffinity db 'SYS_SCHED_GETAFFINITY', 0xA, 0
sys_set_thread_area db 'SYS_SET_THREAD_AREA', 0xA, 0
sys_io_setup db 'SYS_IO_SETUP', 0xA, 0
sys_io_destroy db 'SYS_IO_DESTROY', 0xA, 0
sys_io_getevents db 'SYS_IO_GETEVENTS', 0xA, 0
sys_io_submit db 'SYS_IO_SUBMIT', 0xA, 0
sys_io_cancel db 'SYS_IO_CANCEL', 0xA, 0
sys_get_thread_area db 'SYS_GET_THREAD_AREA', 0xA, 0
sys_lookup_dcookie db 'SYS_LOOKUP_DCOOKIE', 0xA, 0
sys_epoll_create db 'SYS_EPOLL_CREATE', 0xA, 0
sys_epoll_ctl_old db 'SYS_EPOLL_CTL_OLD', 0xA, 0
sys_epoll_wait_old db 'SYS_EPOLL_WAIT_OLD', 0xA, 0
sys_remap_file_pages db 'SYS_REMAP_FILE_PAGES', 0xA, 0
sys_getdents64 db 'SYS_GETDENTS64', 0xA, 0
sys_set_tid_address db 'SYS_SET_TID_ADDRESS', 0xA, 0
sys_restart_syscall db 'SYS_RESTART_SYSCALL', 0xA, 0
sys_semtimedop db 'SYS_SEMTIMEDOP', 0xA, 0
sys_fadvise64 db 'SYS_FADVISE64', 0xA, 0
sys_timer_create db 'SYS_TIMER_CREATE', 0xA, 0
sys_timer_settime db 'SYS_TIMER_SETTIME', 0xA, 0
sys_timer_gettime db 'SYS_TIMER_GETTIME', 0xA, 0
sys_timer_getoverrun db 'SYS_TIMER_GETOVERRUN', 0xA, 0
sys_timer_delete db 'SYS_TIMER_DELETE', 0xA, 0
sys_clock_settime db 'SYS_CLOCK_SETTIME', 0xA, 0
sys_clock_gettime db 'SYS_CLOCK_GETTIME', 0xA, 0
sys_clock_getres db 'SYS_CLOCK_GETRES', 0xA, 0
sys_clock_nanosleep db 'SYS_CLOCK_NANOSLEEP', 0xA, 0
sys_exit_group db 'SYS_EXIT_GROUP', 0xA, 0
sys_epoll_wait db 'SYS_EPOLL_WAIT', 0xA, 0
sys_epoll_ctl db 'SYS_EPOLL_CTL', 0xA, 0
sys_tgkill db 'SYS_TGKILL', 0xA, 0
sys_utimes db 'SYS_UTIMES', 0xA, 0
sys_vserver db 'SYS_VSERVER', 0xA, 0
sys_mbind db 'SYS_MBIND', 0xA, 0
sys_set_mempolicy db 'SYS_SET_MEMPOLICY', 0xA, 0
sys_get_mempolicy db 'SYS_GET_MEMPOLICY', 0xA, 0
sys_mq_open db 'SYS_MQ_OPEN', 0xA, 0
sys_mq_unlink db 'SYS_MQ_UNLINK', 0xA, 0
sys_mq_timedsend db 'SYS_MQ_TIMEDSEND', 0xA, 0
sys_mq_timedreceive db 'SYS_MQ_TIMEDRECEIVE', 0xA, 0
sys_mq_notify db 'SYS_MQ_NOTIFY', 0xA, 0
sys_mq_getsetattr db 'SYS_MQ_GETSETATTR', 0xA, 0
sys_kexec_load db 'SYS_KEXEC_LOAD', 0xA, 0
sys_waitid db 'SYS_WAITID', 0xA, 0
sys_add_key db 'SYS_ADD_KEY', 0xA, 0
sys_request_key db 'SYS_REQUEST_KEY', 0xA, 0
sys_keyctl db 'SYS_KEYCTL', 0xA, 0
sys_ioprio_set db 'SYS_IOPRIO_SET', 0xA, 0
sys_ioprio_get db 'SYS_IOPRIO_GET', 0xA, 0
sys_inotify_init db 'SYS_INOTIFY_INIT', 0xA, 0
sys_inotify_add_watch db 'SYS_INOTIFY_ADD_WATCH', 0xA, 0
sys_inotify_rm_watch db 'SYS_INOTIFY_RM_WATCH', 0xA, 0
sys_migrate_pages db 'SYS_MIGRATE_PAGES', 0xA, 0
sys_openat db 'SYS_OPENAT', 0xA, 0
sys_mkdirat db 'SYS_MKDIRAT', 0xA, 0
sys_mknodat db 'SYS_MKNODAT', 0xA, 0
sys_fchownat db 'SYS_FCHOWNAT', 0xA, 0
sys_futimesat db 'SYS_FUTIMESAT', 0xA, 0
sys_newfstatat db 'SYS_NEWFSTATAT', 0xA, 0
sys_unlinkat db 'SYS_UNLINKAT', 0xA, 0
sys_renameat db 'SYS_RENAMEAT', 0xA, 0
sys_linkat db 'SYS_LINKAT', 0xA, 0
sys_symlinkat db 'SYS_SYMLINKAT', 0xA, 0
sys_readlinkat db 'SYS_READLINKAT', 0xA, 0
sys_fchmodat db 'SYS_FCHMODAT', 0xA, 0
sys_faccessat db 'SYS_FACCESSAT', 0xA, 0
sys_pselect6 db 'SYS_PSELECT6', 0xA, 0
sys_ppoll db 'SYS_PPOLL', 0xA, 0
sys_unshare db 'SYS_UNSHARE', 0xA, 0
sys_set_robust_list db 'SYS_SET_ROBUST_LIST', 0xA, 0
sys_get_robust_list db 'SYS_GET_ROBUST_LIST', 0xA, 0
sys_splice db 'SYS_SPLICE', 0xA, 0
sys_tee db 'SYS_TEE', 0xA, 0
sys_sync_file_range db 'SYS_SYNC_FILE_RANGE', 0xA, 0
sys_vmsplice db 'SYS_VMSPLICE', 0xA, 0
sys_move_pages db 'SYS_MOVE_PAGES', 0xA, 0
sys_utimensat db 'SYS_UTIMENSAT', 0xA, 0
sys_epoll_pwait db 'SYS_EPOLL_PWAIT', 0xA, 0
sys_signalfd db 'SYS_SIGNALFD', 0xA, 0
sys_timerfd_create db 'SYS_TIMERFD_CREATE', 0xA, 0
sys_eventfd db 'SYS_EVENTFD', 0xA, 0
sys_fallocate db 'SYS_FALLOCATE', 0xA, 0
sys_timerfd_settime db 'SYS_TIMERFD_SETTIME', 0xA, 0
sys_timerfd_gettime db 'SYS_TIMERFD_GETTIME', 0xA, 0
sys_accept4 db 'SYS_ACCEPT4', 0xA, 0
sys_signalfd4 db 'SYS_SIGNALFD4', 0xA, 0
sys_eventfd2 db 'SYS_EVENTFD2', 0xA, 0
sys_epoll_create1 db 'SYS_EPOLL_CREATE1', 0xA, 0
sys_dup3 db 'SYS_DUP3', 0xA, 0
sys_pipe2 db 'SYS_PIPE2', 0xA, 0
sys_inotify_init1 db 'SYS_INOTIFY_INIT1', 0xA, 0
sys_preadv db 'SYS_PREADV', 0xA, 0
sys_pwritev db 'SYS_PWRITEV', 0xA, 0
sys_rt_tgsigqueueinfo db 'SYS_RT_TGSIGQUEUEINFO', 0xA, 0
sys_perf_event_open db 'SYS_PERF_EVENT_OPEN', 0xA, 0
sys_recvmmsg db 'SYS_RECVMMSG', 0xA, 0
sys_fanotify_init db 'SYS_FANOTIFY_INIT', 0xA, 0
sys_fanotify_mark db 'SYS_FANOTIFY_MARK', 0xA, 0
sys_prlimit64 db 'SYS_PRLIMIT64', 0xA, 0
sys_name_to_handle_at db 'SYS_NAME_TO_HANDLE_AT', 0xA, 0
sys_open_by_handle_at db 'SYS_OPEN_BY_HANDLE_AT', 0xA, 0
sys_clock_adjtime db 'SYS_CLOCK_ADJTIME', 0xA, 0
sys_syncfs db 'SYS_SYNCFS', 0xA, 0
sys_sendmmsg db 'SYS_SENDMMSG', 0xA, 0
sys_setns db 'SYS_SETNS', 0xA, 0
sys_getcpu db 'SYS_GETCPU', 0xA, 0
sys_process_vm_readv db 'SYS_PROCESS_VM_READV', 0xA, 0
sys_process_vm_writev db 'SYS_PROCESS_VM_WRITEV', 0xA, 0
sys_kcmp db 'SYS_KCMP', 0xA, 0
sys_finit_module db 'SYS_FINIT_MODULE', 0xA, 0
sys_sched_setattr db 'SYS_SCHED_SETATTR', 0xA, 0
sys_sched_getattr db 'SYS_SCHED_GETATTR', 0xA, 0
sys_renameat2 db 'SYS_RENAMEAT2', 0xA, 0
sys_seccomp db 'SYS_SECCOMP', 0xA, 0
sys_getrandom db 'SYS_GETRANDOM', 0xA, 0
sys_memfd_create db 'SYS_MEMFD_CREATE', 0xA, 0
sys_kexec_file_load db 'SYS_KEXEC_FILE_LOAD', 0xA, 0
sys_bpf db 'SYS_BPF', 0xA, 0
stub_execveat db 'STUB_EXECVEAT', 0xA, 0
userfaultfd db 'USERFAULTFD', 0xA, 0
membarrier db 'MEMBARRIER', 0xA, 0
mlock2 db 'MLOCK2', 0xA, 0
copy_file_range db 'COPY_FILE_RANGE', 0xA, 0
preadv2 db 'PREADV2', 0xA, 0
pwritev2 db 'PWRITEV2', 0xA, 0
pkey_mprotect db 'PKEY_MPROTECT', 0xA, 0
pkey_alloc db 'PKEY_ALLOC', 0xA, 0
pkey_free db 'PKEY_FREE', 0xA, 0
statx db 'STATX', 0xA, 0
io_pgetevents db 'IO_PGETEVENTS', 0xA, 0
rseq db 'RSEQ', 0xA, 0
Ending_sys db 'Ending string to help calculate lengths of strings'

sys_calls dq sys_read, sys_write, sys_open, sys_close, sys_stat, sys_fstat, sys_lstat, sys_poll, sys_lseek, sys_mmap, sys_mprotect, sys_munmap, sys_brk, sys_rt_sigaction, sys_rt_sigprocmask, sys_rt_sigreturn, sys_ioctl, sys_pread64, sys_pwrite64, sys_readv, sys_writev, sys_access, sys_pipe, sys_select, sys_sched_yield, sys_mremap, sys_msync, sys_mincore, sys_madvise, sys_shmget, sys_shmat, sys_shmctl, sys_dup, sys_dup2, sys_pause, sys_nanosleep, sys_getitimer, sys_alarm, sys_setitimer, sys_getpid, sys_sendfile, sys_socket, sys_connect, sys_accept, sys_sendto, sys_recvfrom, sys_sendmsg, sys_recvmsg, sys_shutdown, sys_bind, sys_listen, sys_getsockname, sys_getpeername, sys_socketpair, sys_setsockopt, sys_getsockopt, sys_clone, sys_fork, sys_vfork, sys_execve, sys_exit, sys_wait4, sys_kill, sys_uname, sys_semget, sys_semop, sys_semctl, sys_shmdt, sys_msgget, sys_msgsnd, sys_msgrcv, sys_msgctl, sys_fcntl, sys_flock, sys_fsync, sys_fdatasync, sys_truncate, sys_ftruncate, sys_getdents, sys_getcwd, sys_chdir, sys_fchdir, sys_rename, sys_mkdir, sys_rmdir, sys_creat, sys_link, sys_unlink, sys_symlink, sys_readlink, sys_chmod, sys_fchmod, sys_chown, sys_fchown, sys_lchown, sys_umask, sys_gettimeofday, sys_getrlimit, sys_getrusage, sys_sysinfo, sys_times, sys_ptrace, sys_getuid, sys_syslog, sys_getgid, sys_setuid, sys_setgid, sys_geteuid, sys_getegid, sys_setpgid, sys_getppid, sys_getpgrp, sys_setsid, sys_setreuid, sys_setregid, sys_getgroups, sys_setgroups, sys_setresuid, sys_getresuid, sys_setresgid, sys_getresgid, sys_getpgid, sys_setfsuid, sys_setfsgid, sys_getsid, sys_capget, sys_capset, sys_rt_sigpending, sys_rt_sigtimedwait, sys_rt_sigqueueinfo, sys_rt_sigsuspend, sys_sigaltstack, sys_utime, sys_mknod, sys_uselib, sys_personality, sys_ustat, sys_statfs, sys_fstatfs, sys_sysfs, sys_getpriority, sys_setpriority, sys_sched_setparam, sys_sched_getparam, sys_sched_setscheduler, sys_sched_getscheduler, sys_sched_get_priority_max, sys_sched_get_priority_min, sys_sched_rr_get_interval, sys_mlock, sys_munlock, sys_mlockall, sys_munlockall, sys_vhangup, sys_modify_ldt, sys_pivot_root, sys__sysctl, sys_prctl, sys_arch_prctl, sys_adjtimex, sys_setrlimit, sys_chroot, sys_sync, sys_acct, sys_settimeofday, sys_mount, sys_umount2, sys_swapon, sys_swapoff, sys_reboot, sys_sethostname, sys_setdomainname, sys_iopl, sys_ioperm, sys_create_module, sys_init_module, sys_delete_module, sys_get_kernel_syms, sys_query_module, sys_quotactl, sys_nfsservctl, sys_getpmsg, sys_putpmsg, sys_afs_syscall, sys_tuxcall, sys_security, sys_gettid, sys_readahead, sys_setxattr, sys_lsetxattr, sys_fsetxattr, sys_getxattr, sys_lgetxattr, sys_fgetxattr, sys_listxattr, sys_llistxattr, sys_flistxattr, sys_removexattr, sys_lremovexattr, sys_fremovexattr, sys_tkill, sys_time, sys_futex, sys_sched_setaffinity, sys_sched_getaffinity, sys_set_thread_area, sys_io_setup, sys_io_destroy, sys_io_getevents, sys_io_submit, sys_io_cancel, sys_get_thread_area, sys_lookup_dcookie, sys_epoll_create, sys_epoll_ctl_old, sys_epoll_wait_old, sys_remap_file_pages, sys_getdents64, sys_set_tid_address, sys_restart_syscall, sys_semtimedop, sys_fadvise64, sys_timer_create, sys_timer_settime, sys_timer_gettime, sys_timer_getoverrun, sys_timer_delete, sys_clock_settime, sys_clock_gettime, sys_clock_getres, sys_clock_nanosleep, sys_exit_group, sys_epoll_wait, sys_epoll_ctl, sys_tgkill, sys_utimes, sys_vserver, sys_mbind, sys_set_mempolicy, sys_get_mempolicy, sys_mq_open, sys_mq_unlink, sys_mq_timedsend, sys_mq_timedreceive, sys_mq_notify, sys_mq_getsetattr, sys_kexec_load, sys_waitid, sys_add_key, sys_request_key, sys_keyctl, sys_ioprio_set, sys_ioprio_get, sys_inotify_init, sys_inotify_add_watch, sys_inotify_rm_watch, sys_migrate_pages, sys_openat, sys_mkdirat, sys_mknodat, sys_fchownat, sys_futimesat, sys_newfstatat, sys_unlinkat, sys_renameat, sys_linkat, sys_symlinkat, sys_readlinkat, sys_fchmodat, sys_faccessat, sys_pselect6, sys_ppoll, sys_unshare, sys_set_robust_list, sys_get_robust_list, sys_splice, sys_tee, sys_sync_file_range, sys_vmsplice, sys_move_pages, sys_utimensat, sys_epoll_pwait, sys_signalfd, sys_timerfd_create, sys_eventfd, sys_fallocate, sys_timerfd_settime, sys_timerfd_gettime, sys_accept4, sys_signalfd4, sys_eventfd2, sys_epoll_create1, sys_dup3, sys_pipe2, sys_inotify_init1, sys_preadv, sys_pwritev, sys_rt_tgsigqueueinfo, sys_perf_event_open, sys_recvmmsg, sys_fanotify_init, sys_fanotify_mark, sys_prlimit64, sys_name_to_handle_at, sys_open_by_handle_at, sys_clock_adjtime, sys_syncfs, sys_sendmmsg, sys_setns, sys_getcpu, sys_process_vm_readv, sys_process_vm_writev, sys_kcmp, sys_finit_module, sys_sched_setattr, sys_sched_getattr, sys_renameat2, sys_seccomp, sys_getrandom, sys_memfd_create, sys_kexec_file_load, sys_bpf, stub_execveat, userfaultfd, membarrier, mlock2, copy_file_range, preadv2, pwritev2, pkey_mprotect, pkey_alloc, pkey_free, statx, io_pgetevents, rseq, pkey_mprotect, Ending_sys










EPERM db 'EPERM Operation not permitted', 0xA, 0
ENOENT db 'ENOENT No such file or directory', 0xA, 0
ESRCH db 'ESRCH No such process', 0xA, 0
EINTR db 'EINTR Interrupted system call', 0xA, 0
EIO db 'EIO I/O error', 0xA, 0
ENXIO db 'ENXIO No such device or address', 0xA, 0
E2BIG db 'E2BIG Argument list too long', 0xA, 0
ENOEXEC db 'ENOEXEC Exec format error', 0xA, 0
EBADF db 'EBADF Bad file number', 0xA, 0
ECHILD db 'ECHILD No child processes', 0xA, 0
EAGAIN db 'EAGAIN Try again', 0xA, 0
ENOMEM db 'ENOMEM Out of memory', 0xA, 0
EACCES db 'EACCES Permission denied', 0xA, 0
EFAULT db 'EFAULT Bad address', 0xA, 0
ENOTBLK db 'ENOTBLK Block device required', 0xA, 0
EBUSY db 'EBUSY Device or resource busy', 0xA, 0
EEXIST db 'EEXIST File exists', 0xA, 0
EXDEV db 'EXDEV Cross-device link', 0xA, 0
ENODEV db 'ENODEV No such device', 0xA, 0
ENOTDIR db 'ENOTDIR Not a directory', 0xA, 0
EISDIR db 'EISDIR Is a directory', 0xA, 0
EINVAL db 'EINVAL Invalid argument', 0xA, 0
ENFILE db 'ENFILE File table overflow', 0xA, 0
EMFILE db 'EMFILE Too many open files', 0xA, 0
ENOTTY db 'ENOTTY Not a typewriter', 0xA, 0
ETXTBSY db 'ETXTBSY Text file busy', 0xA, 0
EFBIG db 'EFBIG File too large', 0xA, 0
ENOSPC db 'ENOSPC No space left on device', 0xA, 0
ESPIPE db 'ESPIPE Illegal seek', 0xA, 0
EROFS db 'EROFS Read-only file system', 0xA, 0
EMLINK db 'EMLINK Too many links', 0xA, 0
EPIPE db 'EPIPE Broken pipe', 0xA, 0
EDOM db 'EDOM Math argument out of domain of func', 0xA, 0
ERANGE db 'ERANGE Math result not representable', 0xA, 0
EDEADLK db 'EDEADLK Resource deadlock would occur', 0xA, 0
ENAMETOOLONG db 'ENAMETOOLONG File name too long', 0xA, 0
ENOLCK db 'ENOLCK No record locks available', 0xA, 0
ENOSYS db 'ENOSYS Function not implemented', 0xA, 0
ENOTEMPTY db 'ENOTEMPTY Directory not empty', 0xA, 0
ELOOP db 'ELOOP Too many symbolic links encountered', 0xA, 0
EMPTY_0 db 'Empty error code', 0xA, 0
ENOMSG db 'ENOMSG No message of desired type', 0xA, 0
EIDRM db 'EIDRM Identifier removed', 0xA, 0
ECHRNG db 'ECHRNG Channel number out of range', 0xA, 0
EL2NSYNC db 'EL2NSYNC Level 2 not synchronized', 0xA, 0
EL3HLT db 'EL3HLT Level 3 halted', 0xA, 0
EL3RST db 'EL3RST Level 3 reset', 0xA, 0
ELNRNG db 'ELNRNG Link number out of range', 0xA, 0
EUNATCH db 'EUNATCH Protocol driver not attached', 0xA, 0
ENOCSI db 'ENOCSI No CSI structure available', 0xA, 0
EL2HLT db 'EL2HLT Level 2 halted', 0xA, 0
EBADE db 'EBADE Invalid exchange', 0xA, 0
EBADR db 'EBADR Invalid request descriptor', 0xA, 0
EXFULL db 'EXFULL Exchange full', 0xA, 0
ENOANO db 'ENOANO No anode', 0xA, 0
EBADRQC db 'EBADRQC Invalid request code', 0xA, 0
EBADSLT db 'EBADSLT Invalid slot', 0xA, 0
EMPTY_1 db 'Empty error code', 0xA, 0
EBFONT db 'EBFONT Bad font file format', 0xA, 0
ENOSTR db 'ENOSTR Device not a stream', 0xA, 0
ENODATA db 'ENODATA No data available', 0xA, 0
ETIME db 'ETIME Timer expired', 0xA, 0
ENOSR db 'ENOSR Out of streams resources', 0xA, 0
ENONET db 'ENONET Machine is not on the network', 0xA, 0
ENOPKG db 'ENOPKG Package not installed', 0xA, 0
EREMOTE db 'EREMOTE Object is remote', 0xA, 0
ENOLINK db 'ENOLINK Link has been severed', 0xA, 0
EADV db 'EADV Advertise error', 0xA, 0
ESRMNT db 'ESRMNT Srmount error', 0xA, 0
ECOMM db 'ECOMM Communication error on send', 0xA, 0
EPROTO db 'EPROTO Protocol error', 0xA, 0
EMULTIHOP db 'EMULTIHOP Multihop attempted', 0xA, 0
EDOTDOT db 'EDOTDOT RFS specific error', 0xA, 0
EBADMSG db 'EBADMSG Not a data message', 0xA, 0
EOVERFLOW db 'EOVERFLOW Value too large for defined data type', 0xA, 0
ENOTUNIQ db 'ENOTUNIQ Name not unique on network', 0xA, 0
EBADFD db 'EBADFD File descriptor in bad state', 0xA, 0
EREMCHG db 'EREMCHG Remote address changed', 0xA, 0
ELIBACC db 'ELIBACC Can not access a needed shared library', 0xA, 0
ELIBBAD db 'ELIBBAD Accessing a corrupted shared library', 0xA, 0
ELIBSCN db 'ELIBSCN .lib section in a.out corrupted', 0xA, 0
ELIBMAX db 'ELIBMAX Attempting to link in too many shared libraries', 0xA, 0
ELIBEXEC db 'ELIBEXEC Cannot exec a shared library directly', 0xA, 0
EILSEQ db 'EILSEQ Illegal byte sequence', 0xA, 0
ERESTART db 'ERESTART Interrupted system call should be restarted', 0xA, 0
ESTRPIPE db 'ESTRPIPE Streams pipe error', 0xA, 0
EUSERS db 'EUSERS Too many users', 0xA, 0
ENOTSOCK db 'ENOTSOCK Socket operation on non-socket', 0xA, 0
EDESTADDRREQ db 'EDESTADDRREQ Destination address required', 0xA, 0
EMSGSIZE db 'EMSGSIZE Message too long', 0xA, 0
EPROTOTYPE db 'EPROTOTYPE Protocol wrong type for socket', 0xA, 0
ENOPROTOOPT db 'ENOPROTOOPT Protocol not available', 0xA, 0
EPROTONOSUPPORT db 'EPROTONOSUPPORT Protocol not supported', 0xA, 0
ESOCKTNOSUPPORT db 'ESOCKTNOSUPPORT Socket type not supported', 0xA, 0
EOPNOTSUPP db 'EOPNOTSUPP Operation not supported on transport endpoint', 0xA, 0
EPFNOSUPPORT db 'EPFNOSUPPORT Protocol family not supported', 0xA, 0
EAFNOSUPPORT db 'EAFNOSUPPORT Address family not supported by protocol', 0xA, 0
EADDRINUSE db 'EADDRINUSE Address already in use', 0xA, 0
EADDRNOTAVAIL db 'EADDRNOTAVAIL Cannot assign requested address', 0xA, 0
ENETDOWN db 'ENETDOWN Network is down', 0xA, 0
ENETUNREACH db 'ENETUNREACH Network is unreachable', 0xA, 0
ENETRESET db 'ENETRESET Network dropped connection because of reset', 0xA, 0
ECONNABORTED db 'ECONNABORTED Software caused connection abort', 0xA, 0
ECONNRESET db 'ECONNRESET Connection reset by peer', 0xA, 0
ENOBUFS db 'ENOBUFS No buffer space available', 0xA, 0
EISCONN db 'EISCONN Transport endpoint is already connected', 0xA, 0
ENOTCONN db 'ENOTCONN Transport endpoint is not connected', 0xA, 0
ESHUTDOWN db 'ESHUTDOWN Cannot send after transport endpoint shutdown', 0xA, 0
ETOOMANYREFS db 'ETOOMANYREFS Too many references: cannot splice', 0xA, 0
ETIMEDOUT db 'ETIMEDOUT Connection timed out', 0xA, 0
ECONNREFUSED db 'ECONNREFUSED Connection refused', 0xA, 0
EHOSTDOWN db 'EHOSTDOWN Host is down', 0xA, 0
EHOSTUNREACH db 'EHOSTUNREACH No route to host', 0xA, 0
EALREADY db 'EALREADY Operation already in progress', 0xA, 0
EINPROGRESS db 'EINPROGRESS Operation now in progress', 0xA, 0
ESTALE db 'ESTALE Stale NFS file handle', 0xA, 0
EUCLEAN db 'EUCLEAN Structure needs cleaning', 0xA, 0
ENOTNAM db 'ENOTNAM Not a XENIX named type file', 0xA, 0
ENAVAIL db 'ENAVAIL No XENIX semaphores available', 0xA, 0
EISNAM db 'EISNAM Is a named type file', 0xA, 0
EREMOTEIO db 'EREMOTEIO Remote I/O error', 0xA, 0
EDQUOT db 'EDQUOT Quota exceeded', 0xA, 0
ENOMEDIUM db 'ENOMEDIUM No medium found', 0xA, 0
EMEDIUMTYPE db 'EMEDIUMTYPE Wrong medium type', 0xA, 0
ECANCELED db 'ECANCELED Operation Canceled', 0xA, 0
ENOKEY db 'ENOKEY Required key not available', 0xA, 0
EKEYEXPIRED db 'EKEYEXPIRED Key has expired', 0xA, 0
EKEYREVOKED db 'EKEYREVOKED Key has been revoked', 0xA, 0
EKEYREJECTED db 'EKEYREJECTED Key was rejected by service', 0xA, 0
EOWNERDEAD db 'EOWNERDEAD Owner died', 0xA, 0
ENOTRECOVERABLE db 'ENOTRECOVERABLE State not recoverable', 0xA, 0
ENDING_STRING db 'Just so I can make string length calculations.', 0

error_codes dq EPERM, ENOENT, ESRCH, EINTR, EIO, ENXIO, E2BIG, ENOEXEC, EBADF, ECHILD, EAGAIN, ENOMEM, EACCES, EFAULT, ENOTBLK, EBUSY, EEXIST, EXDEV, ENODEV, ENOTDIR, EISDIR, EINVAL, ENFILE, EMFILE, ENOTTY, ETXTBSY, EFBIG, ENOSPC, ESPIPE, EROFS, EMLINK, EPIPE, EDOM, ERANGE, EDEADLK, ENAMETOOLONG, ENOLCK, ENOSYS, ENOTEMPTY, ELOOP, EMPTY_0, ENOMSG, EIDRM, ECHRNG, EL2NSYNC, EL3HLT, EL3RST, ELNRNG, EUNATCH, ENOCSI, EL2HLT, EBADE, EBADR, EXFULL, ENOANO, EBADRQC, EBADSLT, EMPTY_1, EBFONT, ENOSTR, ENODATA, ETIME, ENOSR, ENONET, ENOPKG, EREMOTE, ENOLINK, EADV, ESRMNT, ECOMM, EPROTO, EMULTIHOP, EDOTDOT, EBADMSG, EOVERFLOW, ENOTUNIQ, EBADFD, EREMCHG, ELIBACC, ELIBBAD, ELIBSCN, ELIBMAX, ELIBEXEC, EILSEQ, ERESTART, ESTRPIPE, EUSERS, ENOTSOCK, EDESTADDRREQ, EMSGSIZE, EPROTOTYPE, ENOPROTOOPT, EPROTONOSUPPORT, ESOCKTNOSUPPORT, EOPNOTSUPP, EPFNOSUPPORT, EAFNOSUPPORT, EADDRINUSE, EADDRNOTAVAIL, ENETDOWN, ENETUNREACH, ENETRESET, ECONNABORTED, ECONNRESET, ENOBUFS, EISCONN, ENOTCONN, ESHUTDOWN, ETOOMANYREFS, ETIMEDOUT, ECONNREFUSED, EHOSTDOWN, EHOSTUNREACH, EALREADY, EINPROGRESS, ESTALE, EUCLEAN, ENOTNAM, ENAVAIL, EISNAM, EREMOTEIO, EDQUOT, ENOMEDIUM, EMEDIUMTYPE, ECANCELED, ENOKEY, EKEYEXPIRED, EKEYREVOKED, EKEYREJECTED, EOWNERDEAD, ENOTRECOVERABLE, ENDING_STRING,
section .data
%MACRO DEBUG_REGISTERS 0
;Saving register values

	MOV [register_states], RAX
	MOV [register_states+1*8], RBX
	MOV [register_states+2*8], RCX
	MOV [register_states+3*8], RDX
	MOV [register_states+4*8], RDI
	MOV [register_states+5*8], RSI
	MOV [register_states+6*8], RBP
	MOV [register_states+7*8], RSP
	MOV [saved_registers], RAX
	MOV [saved_registers+1*8], RBX
	MOV [saved_registers+2*8], RCX
	MOV [saved_registers+3*8], RDX
	MOV [saved_registers+4*8], RDI
	MOV [saved_registers+5*8], RSI
	MOV [saved_registers+6*8], RBP
	MOV [saved_registers+7*8], RSP
	
	MOV [register_states_2+0*8], R8
	MOV [register_states_2+1*8], R9
	MOV [register_states_2+2*8], R10
	MOV [register_states_2+3*8], R11
	MOV [register_states_2+4*8], R12
	MOV [register_states_2+5*8], R13
	MOV [register_states_2+6*8], R14
	MOV [register_states_2+7*8], R15
	MOV [saved_registers_2+0*8], R8
	MOV [saved_registers_2+1*8], R9
	MOV [saved_registers_2+2*8], R10
	MOV [saved_registers_2+3*8], R11
	MOV [saved_registers_2+4*8], R12
	MOV [saved_registers_2+5*8], R13
	MOV [saved_registers_2+6*8], R14
	MOV [saved_registers_2+7*8], R15
	
	

	;Align stack
	XOR RDX, RDX
	MOV RDI, 0 ;register_hex & register_states pointer
	MOV RSI, 15 ;register_hex char pointer	
	CALL hex_loop
	XOR RDX, RDX
	MOV RDI, 0 ;register_hex & register_states pointer
	MOV RSI, 15 ;register_hex char pointer	
	CALL hex_loop_2


	;RAX
	MOV RAX,  [register_hex+0*8]
	MOV [debugger_statement+PRINT_OFFSET], RAX
	MOV RAX,  [register_hex+1*8]
	MOV [debugger_statement+PRINT_OFFSET_2], RAX
	;RBX
	MOV RAX,  [register_hex+2*8]
	MOV [debugger_statement+PRINT_OFFSET + 1*PRINT_SPACE], RAX
	MOV RAX,  [register_hex+3*8]
	MOV [debugger_statement+PRINT_OFFSET_2 +1*PRINT_SPACE], RAX
	;RCX
	MOV RAX, [register_hex+4*8]
	MOV [debugger_statement+PRINT_OFFSET + 2*PRINT_SPACE], RAX
	MOV RAX, [register_hex+5*8]
	MOV [debugger_statement+PRINT_OFFSET_2 +2*PRINT_SPACE], RAX
	;RDX
	MOV RAX, [register_hex+6*8]
	MOV [debugger_statement+PRINT_OFFSET + 3*PRINT_SPACE], RAX
	MOV RAX, [register_hex+7*8]
	MOV [debugger_statement+PRINT_OFFSET_2 +3*PRINT_SPACE], RAX
	;RDI
	MOV RAX, [register_hex+8*8]
	MOV [debugger_statement+PRINT_OFFSET + 4*PRINT_SPACE], RAX
	MOV RAX, [register_hex+9*8]
	MOV [debugger_statement+PRINT_OFFSET_2 +4*PRINT_SPACE], RAX
	;RSI
	MOV RAX, [register_hex+10*8]
	MOV [debugger_statement+PRINT_OFFSET + 5*PRINT_SPACE], RAX
	MOV RAX, [register_hex+11*8]
	MOV [debugger_statement+PRINT_OFFSET_2 +5*PRINT_SPACE], RAX
	;RBP
	MOV RAX, [register_hex+12*8]
	MOV [debugger_statement+PRINT_OFFSET + 6*PRINT_SPACE], RAX
	MOV RAX, [register_hex+13*8]
	MOV [debugger_statement+PRINT_OFFSET_2 +6*PRINT_SPACE], RAX
	;RSP
	MOV RAX, [register_hex+14*8]
	MOV [debugger_statement+PRINT_OFFSET + 7*PRINT_SPACE], RAX
	MOV RAX, [register_hex+15*8]
	MOV [debugger_statement+PRINT_OFFSET_2 +7*PRINT_SPACE], RAX
	
	;R8
	MOV RAX, [register_hex_2+0*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 0*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+1*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +0*PRINT_SPACE_2], RAX
	;R9
	MOV RAX, [register_hex_2+2*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 1*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+3*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +1*PRINT_SPACE_2], RAX
	;R10
	MOV RAX, [register_hex_2+4*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 2*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+5*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +2*PRINT_SPACE_2], RAX
	;R11
	MOV RAX, [register_hex_2+6*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 3*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+7*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +3*PRINT_SPACE_2], RAX
	;R12
	MOV RAX, [register_hex_2+8*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 4*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+9*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +4*PRINT_SPACE_2], RAX
	;R13
	MOV RAX, [register_hex_2+10*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 5*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+11*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +5*PRINT_SPACE_2], RAX
	;R14
	MOV RAX, [register_hex_2+12*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 6*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+13*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +6*PRINT_SPACE_2], RAX
	;R15
	MOV RAX, [register_hex_2+14*8]
	MOV [debugger_statement_2+PRINT_OFFSET_3 + 7*PRINT_SPACE_2], RAX
	MOV RAX, [register_hex_2+15*8]
	MOV [debugger_statement_2+PRINT_OFFSET_4 +7*PRINT_SPACE_2], RAX
	
	
	
	MOV RAX, 1 ;SYS_WRITE
	MOV RDI, 1 ;STDOUT
	MOV RSI, debugger_statement
	MOV RDX, debug_length
	SYSCALL
	MOV RAX, 1 ;SYS_WRITE
	MOV RDI, 1 ;STDOUT
	MOV RSI, debugger_statement_2
	MOV RDX, debug_2_length
	SYSCALL
	
	MOV RAX, [saved_registers+0*8]
	MOV RBX, [saved_registers+1*8]
	MOV RCX, [saved_registers+2*8]
	MOV RDX, [saved_registers+3*8]
	MOV RDI, [saved_registers+4*8]
	MOV RSI, [saved_registers+5*8]
	
	MOV R8, [saved_registers_2+0*8]
	MOV R9, [saved_registers_2+1*8]
	MOV R10, [saved_registers_2+2*8]
	MOV R11, [saved_registers_2+3*8]
	MOV R12, [saved_registers_2+4*8]
	MOV R13, [saved_registers_2+5*8]
	MOV R14, [saved_registers_2+6*8]
	MOV R15, [saved_registers_2+7*8]
	
	
	
	
%ENDMACRO

	;Debugger data
	
	debugger_statement db 'Registers:', 0xA, 'RAX: 0x                ', 0xA, 'RBX: 0x                ', 0xA, 'RCX: 0x                ', 0xA, 'RDX: 0x                ', 0xA, 'RDI: 0x                ', 0xA, 'RSI: 0x                ', 0xA, 'RBP: 0x                ', 0xA, 'RSP: 0x                ', 0xA
	debug_length equ $- debugger_statement
	PRINT_OFFSET equ 18
	PRINT_OFFSET_2 equ 26
	PRINT_SPACE equ 24
	
	debugger_statement_2 db 'R8 : 0x                ', 0xA, 'R9 : 0x                ', 0xA, 'R10: 0x                ', 0xA, 'R11: 0x                ', 0xA, 'R12: 0x                ', 0xA, 'R13: 0x                ', 0xA, 'R14: 0x                ', 0xA, 'R15: 0x                ', 0xA
	debug_2_length equ $- debugger_statement_2
	PRINT_OFFSET_3 equ 7
	PRINT_OFFSET_4 equ 15
	PRINT_SPACE_2 equ 24
	
	register_states dq 0, 0, 0, 0, 0, 0, 0, 0
	saved_registers dq 0, 0, 0, 0, 0, 0, 0, 0
	register_hex dq 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	
	register_states_2 dq 0, 0, 0, 0, 0, 0, 0, 0
	saved_registers_2 dq 0, 0, 0, 0, 0, 0, 0, 0
	register_hex_2 dq 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	
	
	hex_chars db '0123456789ABCDEF'
	NEWLINE db 0xA
	
	
	Success db 'Exited successfully', 0xA
	Success_len equ $- Success
	
	SOCK_DESCRIPTOR db 0
	
	;SYSTEM CALLS
	%DEFINE SYS_WRITE 1
	%DEFINE STDOUT 1
	%DEFINE SYS_SOCKET 41
	%DEFINE AF_INET 2
	%DEFINE SOCK_STREAM 1
	%DEFINE SYS_CONNECT 42
	%DEFINE SYS_EXIT 60
section .bss
    
	
	
section .text

	hex_loop:
		MOV RAX, [register_states+RDI*4]
		MOV RBX, 16
		DIV RBX
		MOV [register_states+RDI*4], RAX
		MOV CL, [hex_chars+RDX]
		MOV [register_hex+RDI*8+ RSI], CL
		DEC RSI
		CMP RSI, 0
		JL reset_rsi
		JGE hex_loop
	RET
	reset_rsi:
		ADD RDI, 2
		MOV RSI, 15
		CMP RDI, 16
		JB hex_loop
	RET
	
	hex_loop_2:
		MOV RAX, [register_states_2+RDI*4]
		MOV RBX, 16
		DIV RBX
		MOV [register_states_2+RDI*4], RAX
		MOV CL, [hex_chars+RDX]
		MOV [register_hex_2+RDI*8+RSI], CL
		DEC RSI
		CMP RSI, 0
		JL reset_rsi_2
		JGE hex_loop_2
	RET
	reset_rsi_2:
		ADD RDI, 2
		MOV RSI, 15
		CMP RDI, 16
		JB hex_loop_2
	RET
	
	Error_Handler:
		DEBUG_REGISTERS
		;Sets up error code pointer
		MOV R15, RAX
		IMUL R15, -1
		DEC R15
		
		;Prints system call
		POP R14
		MOV RAX, SYS_WRITE
		MOV RDI, STDOUT
		MOV RSI, [sys_calls+R14*8]
		MOV RDX, [sys_calls+R14*8+8]
		SUB RDX, [sys_calls+R14*8]
		SYSCALL
		;Prints error message
		MOV RAX, SYS_WRITE
		MOV RDI, STDOUT
		MOV RSI, [error_codes+8*R15]
		;Calculates string length
		MOV RDX, [error_codes+8*R15+8]
		SUB RDX, [error_codes+8*R15]
		SYSCALL
		JMP exit
		
	global _start
	
	_start:
		MOV RAX, SYS_SOCKET
		PUSH RAX
		MOV RDI, 0 ;ipv4
		MOV RSI, 0
		SYSCALL
		
		CMP RAX, 0
		JL Error_Handler
		
		exit:
		MOV RAX, SYS_WRITE
		MOV RDI, STDOUT
		MOV RSI, Success
		MOV RDX, Success_len
		SYSCALL
		
		MOV RAX, SYS_EXIT
		XOR RDI, RDI
		SYSCALL
