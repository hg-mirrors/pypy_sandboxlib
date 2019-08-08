import os
import cffi
ffibuilder = cffi.FFI()

ffibuilder.cdef("""
    typedef int... dev_t;
    typedef int... ino_t;
    typedef int... mode_t;
    typedef int... nlink_t;
    typedef int... uid_t;
    typedef int... gid_t;
    typedef int... off_t;
    typedef int... time_t;

    struct stat {
       dev_t     st_dev;         /* ID of device containing file */
       ino_t     st_ino;         /* Inode number */
       mode_t    st_mode;        /* File type and mode */
       nlink_t   st_nlink;       /* Number of hard links */
       uid_t     st_uid;         /* User ID of owner */
       gid_t     st_gid;         /* Group ID of owner */
       dev_t     st_rdev;        /* Device ID (if special file) */
       off_t     st_size;        /* Total size, in bytes */
       time_t    st_atime;       /* last access, integer part only */
       time_t    st_mtime;       /* last modification, integer part only */
       time_t    st_ctime;       /* last status change, integer part only */
       ...;
    };
""")

ffibuilder.set_source("sandboxlib._commonstruct_cffi", """

    #include <sys/types.h>
    #include <sys/stat.h>
    #include <unistd.h>

""")

if __name__ == '__main__':
    ffibuilder.compile(verbose=True)
