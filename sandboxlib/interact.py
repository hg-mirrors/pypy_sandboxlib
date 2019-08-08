import sys, types
import subprocess
from . import sandboxio


def get_sandbox_dump(progrname):
    popen = subprocess.Popen([progrname],
                             stdout=subprocess.PIPE,
                             env={"RPY_SANDBOX_DUMP": "1"})
    out, err = popen.communicate()
    return out

def signature(sig):
    def decorator(func):
        func._sandbox_sig_ = sig
        return func
    return decorator


class VirtualizedProc(object):
    """Control a virtualized sandboxed process, which is given a custom
    view on the filesystem and a custom environment.
    """
    virtual_env = {}
    virtual_cwd = '/tmp'

    def __init__(self, args):
        self.popen = subprocess.Popen(args, stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE)
        self.sandio = sandboxio.SandboxedIO(self.popen)

        #print("Sandboxed subprocess is pid %d" % (self.popen.pid,))
        #print("Press Enter to continue...")
        #sys.stdin.readline()

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
        errors = False
        cls_signatures = cls.collect_signatures()
        for line in dump.splitlines(False):
            key, value = line.split(': ', 1)
            if key == "Version":
                if value != str(sandboxio.VERSION):
                    print("Bad version number: expected %s, got %s" %
                          (sandboxio.VERSION, value))
                    errors = True
            elif key == "Platform":
                if value != sys.platform:
                    print("Bad platform: expected %r, got %r" %
                          (sys.platform, value))
                    errors = True
            elif key == "Funcs":
                for fnname in value.split(' '):
                    if fnname not in cls_signatures:
                        print("Sandboxed function signature not implemented: %s"
                              % (fnname,))
                        errors = True
        if not errors:
            print("All OK")
        return int(errors)

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
        exitcode = self.popen.wait()
        if exitcode != 0:
            print("Subprocess left with exit code %s" % (exitcode,))
            return 1
        else:
            return 0

    @signature("write(ipi)i")
    def s_write(self, fd, buf, count):
        assert fd == 1
        buf = self.sandio.read_buffer(buf, count)
        print("Subprocess wrote: %r" % (buf,))
        return count

    @signature("get_environ()p")
    def s_get_environ(self):
        return self.sandio.malloc(b"\x00" * sandboxio._ptr_size)
