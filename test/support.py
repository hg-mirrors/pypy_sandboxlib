from __future__ import print_function
import py
import os
import subprocess
import time
from sandboxlib.mix_grab_output import MixGrabOutput



class BaseTest(object):

    def execute(self, args, env=None):
        assert isinstance(args, (list, tuple))
        myclass = self.vproccls
        popen = subprocess.Popen(args, executable=self.pypy_c_sandbox, env=env,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE)
        self.popen = popen
        self.virtualizedproc = myclass(popen.stdin, popen.stdout)
        return self.virtualizedproc

    def close(self):
        timeout = 3.0
        while self.popen.poll() is None:
            timeout -= 0.05
            if timeout < 0.0:
                self.popen.terminate()
                raise AssertionError(
                    "timed out waiting for subprocess to finish")
            time.sleep(0.05)

        out = None
        if isinstance(self.virtualizedproc, MixGrabOutput):
            out = self.virtualizedproc.get_all_output().decode('latin1')
            print()
            print('***** Captured stdout/stderr:')
            print(out)
            print('*****')

        assert self.popen.returncode == 0, (
            "subprocess finished with exit code %r" % (self.popen.returncode,))
        return out
