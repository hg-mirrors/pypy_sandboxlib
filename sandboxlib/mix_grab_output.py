from cStringIO import StringIO
from .virtualizedproc import signature


class MixGrabOutput(object):
    write_buffer_limit = 1000000

    @signature("write(ipi)i")
    def s_write(self, fd, p_buf, count):
        """Writes to stdout or stderr are copied to an internal buffer."""

        if fd != 1 and fd != 2:
            return super(MixGrabOutput, self).s_write(fd, p_buf, count)

        data = self.sandio.read_buffer(p_buf, count)
        if not hasattr(self, '_write_buffer'):
            self._write_buffer= StringIO()
        if self._write_buffer.tell() + len(data) > self.write_buffer_limit:
            raise Exception("subprocess is writing too much data on "
                            "stdout/stderr")
        self._write_buffer.write(data)
        return count

    def get_all_output(self):
        if not hasattr(self, '_write_buffer'):
            self._write_buffer= StringIO()
        return self._write_buffer.getvalue()
