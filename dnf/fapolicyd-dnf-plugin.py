#!/usr/bin/python3

import dnf
import os
import stat

class Fapolicyd(dnf.Plugin):

    name = "fapolicyd"
    pipe = "/var/run/fapolicyd/fapolicyd.fifo"
    file = None

    def __init__(self, base, cli):
        print("fapolicyd-plugin is installed and active")
        pass

    def transaction(self):
        print("fapolicy-plugin: sending signal to fapolicy daemon")

        if not os.path.exists(self.pipe):
            print("Pipe does not exist (" + self.pipe + ")")
            print("Perhaps fapolicy-plugin does not have enough permission")
            print("or fapolicyd is not running...")
            return

        if not stat.S_ISFIFO(os.stat(self.pipe).st_mode):
            print(self.pipe + ": is not a pipe!")
            return

        try:
            self.file = open(self.pipe, "w")
        except PermissionError:
            print("fapolicy-plugin does not have write permission: " + self.pipe)
            return

        self.file.write("1")
        self.file.close()

        print("Fapolicyd was notified")

