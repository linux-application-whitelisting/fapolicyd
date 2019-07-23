#!/usr/bin/python3

import dnf
import os
import stat
import sys

class Fapolicyd(dnf.Plugin):

    name = "fapolicyd"
    pipe = "/var/run/fapolicyd/fapolicyd.fifo"
    file = None

    def __init__(self, base, cli):
        pass

    def transaction(self):

        if not os.path.exists(self.pipe):
            sys.stderr.write("Pipe does not exist (" + self.pipe + ")\n")
            sys.stderr.write("Perhaps fapolicy-plugin does not have enough permissions\n")
            sys.stderr.write("or fapolicyd is not running...\n")
            return

        if not stat.S_ISFIFO(os.stat(self.pipe).st_mode):
            sys.stderr.write(self.pipe + ": is not a pipe!\n")
            return

        try:
            self.file = open(self.pipe, "w")
        except PermissionError:
            sys.stderr.write("fapolicy-plugin does not have write permission: " + self.pipe + "\n")
            return

        self.file.write("1")
        self.file.close()
