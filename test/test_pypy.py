import os
from io import BytesIO
from sandboxlib import VirtualizedProc
from sandboxlib.mix_pypy import MixPyPy
from sandboxlib.mix_vfs import MixVFS, Dir, File, RealDir
from sandboxlib.mix_grab_output import MixGrabOutput
from . import support


class TestVirtualizedProc(support.BaseTest):

    def setup_class(cls):
        cls.pypy_c_sandbox = os.path.join(os.path.dirname(__file__),
                                          'pypy-c-sandbox')
        if not os.path.exists(cls.pypy_c_sandbox):
            py.test.skip("make a symlink 'pypy-c-sandbox'")

        lib_python = os.path.join(os.path.dirname(__file__), 'lib-python')
        lib_pypy = os.path.join(os.path.dirname(__file__), 'lib_pypy')

        class PyPyProc(MixPyPy, MixVFS, MixGrabOutput, VirtualizedProc):
            debug_errors = True

            virtual_cwd = "/tmp"

            _vfs_exclude = ['.pyc', '.pyo']
            vfs_root = Dir({
                'bin': Dir({
                    'pypy': File('', mode=0111),
                    'lib-python': RealDir(lib_python, exclude=_vfs_exclude),
                    'lib_pypy': RealDir(lib_pypy, exclude=_vfs_exclude),
                    }),
                 'tmp': Dir({}),
                 })
        cls.vproccls = PyPyProc


    missing_ok = set([
        'ctermid',
    ])

    def test_check_dump(self):
        vp = self.execute(['/tmp/pypy'], env={"RPY_SANDBOX_DUMP": "1"})
        errors = vp.check_dump(self.popen.stdout.read(), self.missing_ok)
        for error in errors:
            print(error)
        assert not errors

    def test_starts(self):
        vp = self.execute(['/bin/pypy', '-c', 'pass'])
        vp.run()
        self.close()

    def test_prints_42(self):
        vp = self.execute(['/bin/pypy', '-c', 'print(6*7)'])
        vp.run()
        self.close()
