import sys
import getopt
from . import interact


def main(argv, cls=interact.VirtualizedProc):
    opts, args = getopt.getopt(argv, '', ['check'])
    dump = False
    for key, value in opts:
        if key == '--check':
            dump = True
        else:
            raise AssertionError("unexpected option %r" % (key,))

    if not args:
        sys.stderr.write("missing argument: program name\n")
        sys.exit(1)

    if dump:
        dump = interact.get_sandbox_dump(args[0])
        sys.stdout.write(dump)
        sys.stdout.write('\n')
        return cls.check_dump(dump)
    else:
        return cls(args).run()
