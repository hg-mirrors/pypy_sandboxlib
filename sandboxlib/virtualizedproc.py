import sys, types
import os, errno, time
from . import sandboxio
from .sandboxio import Ptr, NULL, ptr_size
from ._commonstruct_cffi import ffi, lib


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
        self.sandio.set_errno(error)
        return returns
    return s_error


class VirtualizedProc(object):
    """Controls a virtualized sandboxed process, which is given a custom
    view on the filesystem and a custom environment.
    """

    def __init__(self, child_stdin, child_stdout):
        self.sandio = sandboxio.SandboxedIO(child_stdin, child_stdout)

    @classmethod
    def collect_signatures(cls):
        funcs = {}
        for cls1 in cls.__mro__:
            for value in cls1.__dict__.values():
                if type(value) is types.FunctionType and \
                        hasattr(value, '_sandbox_sig_'):
                    sig = value._sandbox_sig_
                    funcs.setdefault(sig, value)
        return funcs

    @classmethod
    def check_dump(cls, dump):
        errors = []
        cls_signatures = cls.collect_signatures()
        for line in dump.splitlines(False):
            key, value = line.split(': ', 1)
            if key == "Version":
                if value != str(sandboxio.VERSION):
                    errors.append("Bad version number: expected %s, got %s" %
                                  (sandboxio.VERSION, value))
            elif key == "Platform":
                if value != sys.platform:
                    errors.append("Bad platform: expected %r, got %r" %
                                  (sys.platform, value))
            elif key == "Funcs":
                for fnname in value.split(' '):
                    if fnname not in cls_signatures:
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
        raise Exception("subprocess tries to call %s, terminating it" % (
            msg,))

    s_gettimeofday = sigerror("gettimeofday(pp)i")
    s_lstat64 = sigerror("lstat64(pp)i")
    s_open = sigerror("open(pii)i")
    s_stat64 = sigerror("stat64(pp)i")
    s_write = sigerror("write(ipi)i")
    s_uname = sigerror("uname(p)i")

    @signature("time(p)i")
    def s_time(self, p_tloc):
        t = int(self.sandbox_time())
        if p_tloc.addr != 0:
            bytes_data = ffi.buffer(ffi.new("time_t *", t))[:]
            self.sandio.write_buffer(p_tloc, bytes_data)
        return t

    def sandbox_time(self):
        """Default implementation: return a fixed result"""
        return time.mktime((2019, 8, 1, 0, 0, 0, 0, 0, 0))   # Aug 1st, 2019

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
        cwd = self.sandbox_getcwd()
        if len(cwd) >= size:
            self.sandio.set_errno(errno.ERANGE)
            return NULL
        self.sandio.write_buffer(p_buf, cwd + b'\x00')
        return p_buf

    def sandbox_getcwd(self):
        """Default implementation: returns '/'."""
        return b"/"

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
