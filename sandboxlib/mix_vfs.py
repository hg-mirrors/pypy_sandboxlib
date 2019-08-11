import sys
import os, errno, stat
from io import BytesIO
from .virtualizedproc import signature
from .sandboxio import NULL
from ._commonstruct_cffi import ffi, lib

MAX_PATH = 256
UID = 1000
GID = 1000
INO_COUNTER = 0


class FSObject(object):
    read_only = True

    def stat(self):
        try:
            st_ino = self._st_ino
        except AttributeError:
            global INO_COUNTER
            INO_COUNTER += 1
            st_ino = self._st_ino = INO_COUNTER
        st_mode = self.kind
        st_mode |= stat.S_IWUSR | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
        if self.is_dir():
            st_mode |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        if self.read_only:
            st_uid = 0       # read-only files are virtually owned by root
            st_gid = 0
        else:
            st_uid = UID     # read-write files are owned by this virtual user
            st_gid = GID
        return ffi.new("struct stat *", dict(
            st_ino = st_ino,
            st_dev = 1,
            st_nlink = 1,
            st_size = self.getsize(),
            st_mode = st_mode,
            st_uid = st_uid,
            st_gid = st_gid))

    def access(self, mode):
        s = self.stat()
        e_mode = s.st_mode & stat.S_IRWXO
        if UID == s.st_uid:
            e_mode |= (s.st_mode & stat.S_IRWXU) >> 6
        if GID == s.st_gid:
            e_mode |= (s.st_mode & stat.S_IRWXG) >> 3
        return (e_mode & mode) == mode

    def keys(self):
        raise OSError(errno.ENOTDIR, self)

    def join(self, name):
        raise OSError(errno.ENOTDIR, self)

    def open(self):
        raise OSError(errno.EACCES, self)

    def getsize(self):
        return 0

    def is_dir(self):
        return stat.S_ISDIR(self.kind)


class Dir(FSObject):
    kind = stat.S_IFDIR
    def __init__(self, entries={}):
        self.entries = entries
    def keys(self):
        return sorted(self.entries.keys())
    def join(self, name):
        try:
            return self.entries[name]
        except KeyError:
            raise OSError(errno.ENOENT, name)

class RealDir(Dir):
    # If show_dotfiles=False, we pretend that all files whose name starts
    # with '.' simply don't exist.  If follow_links=True, then symlinks are
    # transparently followed (they look like a regular file or directory to
    # the sandboxed process).  If follow_links=False, the subprocess is
    # not allowed to access them at all.  Finally, exclude is a list of
    # file endings that we filter out (note that we also filter out files
    # with the same ending but a different case, to be safe).
    def __init__(self, path, show_dotfiles=False, follow_links=False,
                 exclude=[]):
        self.path = path
        self.show_dotfiles = show_dotfiles
        self.follow_links  = follow_links
        self.exclude       = [excl.lower() for excl in exclude]
    def __repr__(self):
        return '<RealDir %s>' % (self.path,)
    def keys(self):
        names = os.listdir(self.path)
        if not self.show_dotfiles:
            names = [name for name in names if not name.startswith('.')]
        for excl in self.exclude:
            names = [name for name in names if not name.lower().endswith(excl)]
        return sorted(names)
    def join(self, name):
        if name.startswith('.') and not self.show_dotfiles:
            raise OSError(errno.ENOENT, name)
        for excl in self.exclude:
            if name.lower().endswith(excl):
                raise OSError(errno.ENOENT, name)
        path = os.path.join(self.path, name)
        if self.follow_links:
            st = os.stat(path)
        else:
            st = os.lstat(path)
        if stat.S_ISDIR(st.st_mode):
            return RealDir(path, show_dotfiles = self.show_dotfiles,
                                 follow_links  = self.follow_links,
                                 exclude       = self.exclude)
        elif stat.S_ISREG(st.st_mode):
            return RealFile(path)
        else:
            # don't allow access to symlinks and other special files
            raise OSError(errno.EACCES, path)

class File(FSObject):
    kind = stat.S_IFREG
    def __init__(self, data, mode=0):
        self.data = data
        self.kind |= mode
    def getsize(self):
        return len(self.data)
    def open(self):
        return BytesIO(self.data)

class RealFile(File):
    def __init__(self, path, mode=0):
        self.path = path
        self.kind |= mode
    def __repr__(self):
        return '<RealFile %s>' % (self.path,)
    def getsize(self):
        return os.stat(self.path).st_size
    def open(self):
        try:
            return open(self.path, "rb")
        except IOError as e:
            raise OSError(e.errno, "open failed")


class OpenDir(object):
    def __init__(self, node):
        self.node = node
        self.iter_names = iter(node.keys())
    def readdir(self):
        return next(self.iter_names)


def vfs_signature(sig, filearg=None):
    def decorate(func):
        @signature(sig)
        def wrapper(self, *args):
            try:
                return func(self, *args) or 0
            except OSError as e:
                if self.debug_errors:
                    filename = ""
                    if filearg is not None:
                        filename = repr(self.fetch_path(args[filearg]))
                    msg = "subprocess: vfs: %s(%s) => %s\n" % (
                        sig.split('(')[0],
                        filename,
                        errno.errorcode.get(e.errno, 'Errno %s' % e.errno))
                    sys.stderr.write(msg)
                self.sandio.set_errno(e.errno)
                return -1
        return wrapper
    return decorate


class MixVFS(object):
    """A virtual, read-only file system.

    Call with 'vfs_root = root directory' in the constructor or by
    adding an attribute 'vfs_root' on the subclass directory.
    This should be a hierarchy built using the classes above.
    """
    virtual_fd_range = range(3, 50)
    VFS_MAX_DIRS_OPEN = 32


    def __init__(self, *args, **kwds):
        try:
            self.vfs_root = kwds.pop('vfs_root')
        except KeyError:
            assert hasattr(self, 'vfs_root'), (
                "must pass a vfs_root argument to the constructor, or assign "
                "a vfs_root class attribute directory in the subclass")
        self.vfs_open_fds = {}
        self.vfs_open_dirs = {}
        super(MixVFS, self).__init__(*args, **kwds)

    def fetch_path(self, p_pathname):
        if isinstance(p_pathname, str):
            return p_pathname
        return self.sandio.read_charp(p_pathname, MAX_PATH).decode('utf-8')

    def vfs_getnode(self, p_pathname):
        path = self.fetch_path(p_pathname)
        all_components = [self.vfs_root]
        for name in path.split('/'):
            if name == '..':
                if len(all_components) > 1:
                    del all_components[-1]
            elif name and name != '.':
                all_components.append(all_components[-1].join(name))
        return all_components[-1]

    def vfs_write_stat(self, p_statbuf, node):
        ffi_stat = node.stat()
        bytes_data = ffi.buffer(ffi_stat)[:]
        self.sandio.write_buffer(p_statbuf, bytes_data)

    def vfs_allocate_fd(self, f, node):
        assert not node.is_dir()
        for fd in self.virtual_fd_range:
            if fd not in self.vfs_open_fds:
                self.vfs_open_fds[fd] = (f, node)
                return fd
        else:
            raise OSError(errno.EMFILE, "trying to open too many files")

    def vfs_get_file(self, fd):
        """Return the open file for file descriptor `fd`."""
        try:
            return self.vfs_open_fds[fd][0]
        except KeyError:
            raise OSError(errno.EBADF, "bad file descriptor")

    @vfs_signature("stat64(pp)i", filearg=0)
    def s_stat64(self, p_pathname, p_statbuf):
        node = self.vfs_getnode(p_pathname)
        self.vfs_write_stat(p_statbuf, node)

    @vfs_signature("lstat64(pp)i", filearg=0)
    def s_lstat64(self, p_pathname, p_statbuf):
        node = self.vfs_getnode(p_pathname)
        self.vfs_write_stat(p_statbuf, node)

    @vfs_signature("fstat64(ip)i")
    def s_fstat64(self, fd, p_statbuf):
        try:
            f, node = self.vfs_open_fds[fd]
        except KeyError:
            raise OSError(errno.EBADF, "bad file descriptor")
        self.vfs_write_stat(p_statbuf, node)

    @vfs_signature("access(pi)i", filearg=0)
    def s_access(self, p_pathname, mode):
        node = self.vfs_getnode(p_pathname)
        if not node.access(mode):
            raise OSError(errno.EACCES, node)

    @vfs_signature("open(pii)i", filearg=0)
    def s_open(self, p_pathname, flags, mode):
        node = self.vfs_getnode(p_pathname)
        write_mode = flags & (os.O_RDONLY|os.O_WRONLY|os.O_RDWR) != os.O_RDONLY
        if not node.access(os.W_OK if write_mode else os.R_OK):
            raise OSError(errno.EACCES, node)
        assert not write_mode, "open: write mode not implemented"
        # all other flags are ignored
        f = node.open()
        return self.vfs_allocate_fd(f, node)

    @vfs_signature("close(i)i")
    def s_close(self, fd):
        f = self.vfs_get_file(fd)
        del self.vfs_open_fds[fd]
        f.close()

    @vfs_signature("read(ipi)i")
    def s_read(self, fd, p_buf, count):
        f = self.vfs_get_file(fd)
        if count < 0:
            count = 0
        # don't try to read more than 256KB at once here
        data = f.read(min(count, 256*1024))
        self.sandio.write_buffer(p_buf, data)
        return len(data)

    @vfs_signature("opendir(p)p")
    def s_opendir(self, p_name):
        # we pretend that "DIR *" pointers are actually implemented as
        # "struct dirent *", where we store the result of each readdir()
        if len(self.vfs_open_dirs) >= self.VFS_MAX_DIRS_OPEN:
            raise OSError(errno.EMFILE, "trying to open too many directories")
        node = self.vfs_getnode(p_name)
        fdir = OpenDir(node)
        p = self.sandio.malloc(b'\x00' * ffi.sizeof("struct dirent"))
        self.vfs_open_dirs[p.addr] = fdir
        return p

    @vfs_signature("readdir(p)p")
    def s_readdir(self, p_dir):
        fdir = self.vfs_open_dirs[p_dir.addr]
        try:
            name = fdir.readdir()
        except StopIteration:
            return NULL
        subnode = fdir.node.join(name)
        st = subnode.stat()
        dirent = ffi.new("struct dirent *")
        dirent.d_ino = st.st_ino
        dirent.d_reclen = ffi.sizeof("struct dirent")
        if subnode.is_dir():
            dirent.d_type = lib.DT_DIR
        else:
            dirent.d_type = lib.DT_REG
        name = name.encode('utf-8') + b'\x00'
        n = len(name)
        if n > ffi.sizeof(dirent.d_name):
            raise OSError(errno.EOVERFLOW, subnode)
        ffi.memmove(dirent.d_name, name, n)
        bytes_data = ffi.buffer(dirent)[:]
        self.sandio.write_buffer(p_dir, bytes_data)
        return p_dir

    @vfs_signature("closedir(p)i")
    def s_closedir(self, p_dir):
        del self.vfs_open_dirs[p_dir.addr]
        self.sandio.free(p_dir)
