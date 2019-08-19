import sys, types
import os, errno, time
from . import sandboxio
from .sandboxio import Ptr, NULL, ptr_size
from ._commonstruct_cffi import ffi


def signature(sig):
    def decorator(func):
        func._sandbox_sig_ = sig
        return func
    return decorator

def sigerror(sig, error=errno.ENOSYS, returns=-1):
    retcode = sig[-1]
    if retcode == 'i':
        if type(returns) is not int:
            raise Exception("%s: 'returns' should be an int" % sig)
    elif retcode == 'p':
        if type(returns) is not Ptr:
            raise Exception("%s: 'returns' should be a Ptr" % sig)
    elif retcode == 'd':
        if type(returns) is not float:
            raise Exception("%s: 'returns' should be a float" % sig)
    elif retcode == 'v':
        if returns is not None:
            raise Exception("%s: 'returns' should be None" % sig)
    else:
        raise ValueError("%r: invalid return type code" % (sig,))

    @signature(sig)
    def s_error(self, *args):
        if self.debug_errors:
            sys.stderr.write("subprocess: stub: %s\n" % sig)
        self.sandio.set_errno(error)
        return returns
    return s_error


class VirtualizedProc(object):
    """Controls a virtualized sandboxed process, which is given a custom
    view on the filesystem and a custom environment.
    """
    debug_errors = False
    virtual_uid = 1000
    virtual_gid = 1000
    virtual_pid = 4200
    virtual_cwd = "/"
    virtual_time = time.mktime((2019, 8, 1, 0, 0, 0, 0, 0, 0))
    # ^^^ Aug 1st, 2019.  Subclasses can overwrite with a property
    # to get the current time dynamically, too


    def __init__(self, child_stdin, child_stdout):
        self.sandio = sandboxio.SandboxedIO(child_stdin, child_stdout)

    @classmethod
    def collect_signatures(cls):
        funcs = {}
        for cls1 in cls.__mro__:
            for value in cls1.__dict__.values():
                if type(value) is types.FunctionType and \
                        hasattr(value, '_sandbox_sig_'):
                    sig = value._sandbox_sig_.encode('ascii')
                    funcs.setdefault(sig, value)
        return funcs

    @classmethod
    def check_dump(cls, dump, missing_ok=set()):
        errors = []
        cls_signatures = cls.collect_signatures()
        dump = dump.decode('ascii')
        for line in dump.splitlines(False):
            key, value = line.split(': ', 1)
            if key == "Version":
                if value != str(sandboxio.VERSION):
                    errors.append("Bad version number: expected %s, got %s" %
                                  (sandboxio.VERSION, value))
            elif key == "Platform":
                expected = sys.platform
                if expected in ['linux2', 'linux3']:
                    expected = 'linux'
                got = value
                if got in ['linux2', 'linux3']:
                    got = 'linux'
                if got != expected:
                    errors.append("Bad platform: expected %r, got %r" %
                                  (expected, value))
            elif key == "Funcs":
                for fnname in value.split(' '):
                    if (fnname.encode('ascii') not in cls_signatures and
                            fnname not in missing_ok):
                        errors.append("Sandboxed function signature not "
                                      "implemented: %s" % (fnname,))
        return errors

    def run(self):
        cls_signatures = self.collect_signatures()
        sandio = self.sandio
        while True:
            try:
                msg, args = sandio.read_message()
            except EOFError:
                break
            try:
                sigfunc = cls_signatures[msg]
            except KeyError:
                self.handle_missing_signature(msg, args)
            else:
                result = sigfunc(self, *args)
                sandio.write_result(result)

    def handle_missing_signature(self, msg, args):
        raise Exception("subprocess tries to call %r, terminating it" % (
            msg,))

    s_access         = sigerror("access(pi)i")
    s_chdir          = sigerror("chdir(p)i")
    s_chmod          = sigerror("chmod(pi)i")
    s_chown          = sigerror("chown(pii)i")
    s_chroot         = sigerror("chroot(p)i")
    s_clock_getres   = sigerror("clock_getres(ip)i")
    s_clock_gettime  = sigerror("clock_gettime(ip)i")
    s_close          = sigerror("close(i)i")
    s_closedir       = sigerror("closedir(p)i")
    s_confstr        = sigerror("confstr(ipi)i", errno.EINVAL, 0)
    s_dup            = sigerror("dup(i)i")
    s_dup2           = sigerror("dup2(ii)i")
    s_execv          = sigerror("execv(pp)i")
    s_execve         = sigerror("execve(ppp)i")
    s_fchdir         = sigerror("fchdir(i)i")
    s_fchmod         = sigerror("fchmod(ii)i")
    s_fchown         = sigerror("fchown(iii)i")
    s_fcntl          = sigerror("fcntl(iii)i")
    s_fdatasync      = sigerror("fdatasync(i)i")
    s_fork           = sigerror("fork()i")
    s_forkpty        = sigerror("forkpty(pppp)i")
    s_fpathconf      = sigerror("fpathconf(ii)i")
    s_fstat64        = sigerror("fstat64(ip)i")
    s_fstatvfs       = sigerror("fstatvfs(ip)i")
    s_fsync          = sigerror("fsync(i)i")
    s_ftruncate      = sigerror("ftruncate(ii)i")
    s_getloadavg     = sigerror("getloadavg(pi)i")
    s_getlogin       = sigerror("getlogin()p", returns=NULL)
    s_getpgid        = sigerror("getpgid(i)i")
    s_getpgrp        = sigerror("getpgrp()i")    # supposed not to fail...
    s_getrusage      = sigerror("getrusage(ip)i")
    s_getsid         = sigerror("getsid(i)i")
    s_gettimeofday   = sigerror("gettimeofday(pp)i")
    s_initgroups     = sigerror("initgroups(pi)i", errno.EPERM)
    s_isatty         = sigerror("isatty(i)i")
    s_kill           = sigerror("kill(ii)i")
    s_killpg         = sigerror("killpg(ii)i")
    s_lchown         = sigerror("lchown(pii)i")
    s_link           = sigerror("link(pp)i")
    s_lseek          = sigerror("lseek(iii)i")
    s_lstat64        = sigerror("lstat64(pp)i")
    s_mkdir          = sigerror("mkdir(pi)i")
    s_mkfifo         = sigerror("mkfifo(pi)i")
    s_mknod          = sigerror("mknod(pii)i")
    s_nice           = sigerror("nice(i)i")
    s_open           = sigerror("open(pii)i")
    s_opendir        = sigerror("opendir(p)p", returns=NULL)
    s_openpty        = sigerror("openpty(ppppp)i")
    s_pathconf       = sigerror("pathconf(pi)i")
    s_pipe           = sigerror("pipe(p)i")
    s_pipe2          = sigerror("pipe2(pi)i")
    s_putenv         = sigerror("putenv(p)i")
    s_read           = sigerror("read(ipi)i")
    s_readdir        = sigerror("readdir(p)p", returns=NULL)
    s_readlink       = sigerror("readlink(ppi)i")
    s_rename         = sigerror("rename(pp)i")
    s_rmdir          = sigerror("rmdir(p)i")
    s_select         = sigerror("select(ipppp)i")
    s_setegid        = sigerror("setegid(i)i", errno.EPERM)
    s_seteuid        = sigerror("seteuid(i)i", errno.EPERM)
    s_setgid         = sigerror("setgid(i)i", errno.EPERM)
    s_setgroups      = sigerror("setgroups(ip)i", errno.EPERM)
    s_setpgid        = sigerror("setpgid(ii)i", errno.EPERM)
    s_setpgrp        = sigerror("setpgrp()i", errno.EPERM)
    s_setregid       = sigerror("setregid(ii)i", errno.EPERM)
    s_setresgid      = sigerror("setresgid(iii)i", errno.EPERM)
    s_setresuid      = sigerror("setresuid(iii)i", errno.EPERM)
    s_setreuid       = sigerror("setreuid(ii)i", errno.EPERM)
    s_setsid         = sigerror("setsid()i")
    s_setuid         = sigerror("setuid(i)i", errno.EPERM)
    s_stat64         = sigerror("stat64(pp)i")
    s_statvfs        = sigerror("statvfs(pp)i")
    s_symlink        = sigerror("symlink(pp)i")
    s_sysconf        = sigerror("sysconf(i)i")
    s_system         = sigerror("system(p)i")
    s_tcgetpgrp      = sigerror("tcgetpgrp(i)i", errno.ENOTTY)
    s_tcsetpgrp      = sigerror("tcsetpgrp(ii)i", errno.ENOTTY)
    s_times          = sigerror("times(p)i")
    s_ttyname        = sigerror("ttyname(i)p", returns=NULL)
    s_umask          = sigerror("umask(i)i")
    s_uname          = sigerror("uname(p)i")
    s_unlink         = sigerror("unlink(p)i")
    s_unsetenv       = sigerror("unsetenv(p)i")
    s_utime          = sigerror("utime(pp)i")
    s_utimes         = sigerror("utimes(pp)i")
    s_waitpid        = sigerror("waitpid(ipi)i")
    s_write          = sigerror("write(ipi)i")

    # extra functions needed for pypy3
    s_clock          = sigerror("clock()i")
    s_clock_settime  = sigerror("clock_settime(ip)i")
    s_dirfd          = sigerror("dirfd(p)i")
    s_faccessat      = sigerror("faccessat(ipii)i")
    s_fchmodat       = sigerror("fchmodat(ipii)i")
    s_fchownat       = sigerror("fchownat(ipiii)i")
    s_fdopendir      = sigerror("fdopendir(i)p", returns=NULL)
    s_fexecve        = sigerror("fexecve(ipp)i")
    s_fgetxattr      = sigerror("fgetxattr(ippi)i")
    s_fileno         = sigerror("fileno(p)i", errno.EBADF)
    s_flistxattr     = sigerror("flistxattr(ipi)i")
    s_fremovexattr   = sigerror("fremovexattr(ip)i")
    s_fsetxattr      = sigerror("fsetxattr(ippii)i")
    s_fstatat64      = sigerror("fstatat64(ippi)i")
    s_futimens       = sigerror("futimens(ip)i")
    s_getpriority    = sigerror("getpriority(ii)i")
    s_getxattr       = sigerror("getxattr(pppi)i")
    s_ioctl          = sigerror("ioctl(iip)i")
    s_lgetxattr      = sigerror("lgetxattr(pppi)i")
    s_linkat         = sigerror("linkat(ipipi)i")
    s_listxattr      = sigerror("listxattr(ppi)i")
    s_llistxattr     = sigerror("llistxattr(ppi)i")
    s_lockf          = sigerror("lockf(iii)i")
    s_lremovexattr   = sigerror("lremovexattr(pp)i")
    s_lsetxattr      = sigerror("lsetxattr(pppii)i")
    s_mkdirat        = sigerror("mkdirat(ipi)i")
    s_mkfifoat       = sigerror("mkfifoat(ipi)i")
    s_mknodat        = sigerror("mknodat(ipii)i")
    s_openat         = sigerror("openat(ipii)i")
    s_posix_fadvise  = sigerror("posix_fadvise(iiii)i", returns=errno.ENOSYS)
    s_posix_fallocate= sigerror("posix_fallocate(iii)i", returns=errno.ENOSYS)
    s_pread          = sigerror("pread(ipii)i")
    s_pwrite         = sigerror("pwrite(ipii)i")
    s_readlinkat     = sigerror("readlinkat(ippi)i")
    s_removexattr    = sigerror("removexattr(pp)i")
    s_renameat       = sigerror("renameat(ipip)i")
    s_rpy_dup2_noninheritable = sigerror("rpy_dup2_noninheritable(ii)i")
    s_rpy_dup_noninheritable = sigerror("rpy_dup_noninheritable(i)i")
    s_rpy_get_status_flags= sigerror("rpy_get_status_flags(i)i")
    s_rpy_set_status_flags= sigerror("rpy_set_status_flags(ii)i")
    s_sched_get_priority_max= sigerror("sched_get_priority_max(i)i")
    s_sched_get_priority_min= sigerror("sched_get_priority_min(i)i")
    s_sendfile       = sigerror("sendfile(iipi)i")
    s_setpriority    = sigerror("setpriority(iii)i")
    s_setxattr       = sigerror("setxattr(pppii)i")
    s_symlinkat      = sigerror("symlinkat(pip)i")
    s_unlinkat       = sigerror("unlinkat(ipi)i")
    s_utimensat      = sigerror("utimensat(ippi)i")


    @signature("time(p)i")
    def s_time(self, p_tloc):
        t = int(self.virtual_time)
        if p_tloc.addr != 0:
            bytes_data = ffi.buffer(ffi.new("time_t *", t))[:]
            self.sandio.write_buffer(p_tloc, bytes_data)
        return t

    @signature("get_environ()p")
    def s_get_environ(self):
        """Default implementation: the 'environ' variable points to a NULL
        pointer, i.e. the environment is empty."""
        if not hasattr(self, '_alloc_null_environ'):
            self._alloc_null_environ = self.sandio.malloc(b"\x00" * ptr_size)
        return self._alloc_null_environ

    @signature("getenv(p)p")
    def s_getenv(self, p_name):
        """Default implementation: getenv() returns NULL."""
        return NULL

    @signature("getcwd(pi)p")
    def s_getcwd(self, p_buf, size):
        cwd = self.virtual_cwd.encode('utf-8')
        if len(cwd) >= size:
            self.sandio.set_errno(errno.ERANGE)
            return NULL
        self.sandio.write_buffer(p_buf, cwd + b'\x00')
        return p_buf

    @signature("strerror(i)p")
    def s_strerror(self, n):
        """Default implementation: strerror() returns the real result,
        with caching and a hard-coded maximum on the number of such
        strings returned."""
        if not hasattr(self, '_strerror_cache'):
            self._strerror_cache = {}
        if n not in self._strerror_cache:
            if len(self._strerror_cache) > 1000:
                raise Exception("subprocess calls strerror(n) with too many "
                                "values of n, terminating it")
            result = os.strerror(n)
            if not isinstance(result, bytes):
                result = result.encode('utf-8')
            self._strerror_cache[n] = self.sandio.malloc(result + b'\x00')
        return self._strerror_cache[n]

    @signature("_exit(i)v")
    def s__exit(self, exitcode):
        raise Exception("subprocess called _exit(%s)" % (exitcode,))

    @signature("getuid()i")
    def s_getuid(self):
        return self.virtual_uid

    @signature("getgid()i")
    def s_getgid(self):
        return self.virtual_gid

    @signature("geteuid()i")
    def s_geteuid(self):
        return self.virtual_uid

    @signature("getegid()i")
    def s_getegid(self):
        return self.virtual_gid

    @signature("getresuid(ppp)i")
    def s_getresuid(self, p_ruid, p_euid, p_suid):
        bytes_data = ffi.buffer(ffi.new("uid_t *", self.virtual_uid))[:]
        self.sandio.write_buffer(p_ruid, bytes_data)
        self.sandio.write_buffer(p_euid, bytes_data)
        self.sandio.write_buffer(p_suid, bytes_data)
        return 0

    @signature("getresgid(ppp)i")
    def s_getresgid(self, p_rgid, p_egid, p_sgid):
        bytes_data = ffi.buffer(ffi.new("git_t *", self.virtual_gid))[:]
        self.sandio.write_buffer(p_rgid, bytes_data)
        self.sandio.write_buffer(p_egid, bytes_data)
        self.sandio.write_buffer(p_sgid, bytes_data)
        return 0

    @signature("getgroups(ip)i")
    def s_getgroups(self, size, p_list):
        return 0

    @signature("getpid()i")
    def s_getpid(self):
        return self.virtual_pid

    @signature("getppid()i")
    def s_getppid(self):
        return 1     # emulates reparented to 'init'

    @signature("pypy__allow_attach()v")
    def s_pypy__allow_attach(self):
        return None

    #@signature("syscall(ipii)i")
    #def s_syscall(self, *args):
    #    raise Exception("subprocess tried to issue a direct syscall()")

    @signature("ctermid(p)p")
    def s_ctermid(self, s_p):
        if s_p.addr != 0:
            raise Exception("subprocess tried to call ctermid(non-NULL)"
                            " which is not implemented")
        if not hasattr(self, '_alloc_dev_tty'):
            self._alloc_dev_tty = self.sandio.malloc(b"/dev/tty\x00")
        return self._alloc_dev_tty

    @signature("get_stdout()p")
    def s_get_stdout(self, *args):
        raise Exception("subprocess calls the unsupported RPython "
                        "get_stdout() helper")

    @signature("rewinddir(p)v")
    def s_rewinddir(self, *args):
        raise Exception("subprocess calls the unsupported rewinddir() function")

    @signature("rpy_cpu_count()i")
    def s_rpy_cpu_count(self, *args):
        return 1

    @signature("rpy_get_inheritable(i)i")
    def s_rpy_get_inheritable(self, fd):
        return 0     # ignored

    @signature("rpy_set_inheritable(ii)i")
    def s_rpy_set_inheritable(self, fd, inheritable):
        return 0     # ignored

    @signature("sched_yield()i")
    def s_sched_yield(self):
        return 0     # always succeeds

    @signature("sync()v")
    def s_sync(self):
        if self.debug_errors:
            sys.stderr.write("subprocess: sync ignored\n")
