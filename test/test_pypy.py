from sandboxlib import VirtualizedProc
from sandboxlib.mix_pypy import MixPyPy
from sandboxlib.mix_grab_output import MixGrabOutput
from . import support


class TestVirtualizedProc(support.BaseTest):
    class vproccls(MixPyPy, MixGrabOutput, VirtualizedProc):
        pass

    def test_check_dump(self):
        vp = self.execute(['/tmp/pypy'], env={"RPY_SANDBOX_DUMP": "1"})
        errors = vp.check_dump(self.popen.stdout.read())
        for error in errors:
            print(error)
        assert not errors

    def test_starts(self):
        vp = self.execute(['/tmp/pypy', '-c', 'pass'])
        vp.run()
        self.close()

    def test_prints_42(self):
        vp = self.execute(['/tmp/pypy', '-c', 'print(6*7)'])
        vp.run()
        self.close()
