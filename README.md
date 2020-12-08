File Access Policy Daemon
=========================

[![Build Status](https://travis-ci.com/linux-application-whitelisting/fapolicyd.svg?branch=master)](https://travis-ci.com/linux-application-whitelisting/fapolicyd)

This is a simple application whitelisting daemon for Linux.

DEPENDENCIES (fedora)
---------------------
* gcc
* autoconf
* automake
* libtool
* make
* libudev-devel
* kernel-headers
* systemd-devel
* libgcrypt-devel
* rpm-devel (optional)
* file
* file-devel
* libcap-ng-devel
* libseccomp-devel
* lmdb-devel
* uthash-devel
* python3-devel
* kernel >= 4.20 (Must support FANOTIFY_OPEN_EXEC_PERM. See [1] below.)

BUILDING
--------
To build from the repo after cloning:

```
$ cd fapolicyd
$ ./autogen.sh
$ ./configure --with-audit --disable-shared
$ make
$ make dist
```

This will create a tarball. You can use the new tarball with the spec file
and create your own rpm. If you want to experiment without installing, just
run make with no arguments. It should run fine from where it was built as
long as you put the configuration files in /etc/fapolicyd (fapolicyd.rules,
fapolicyd.trust, fapolicyd.conf).

Note that the shipped policy expects that auditing is enabled. This is done
by passing --with-audit to ./configure.

The use of rpm as a trust source is now optional. You can run ./configure
passing --without-rpm and it will not link against librpm. In this mode, it
purely uses the file database in fapolicyd.trust. If rpm is used, then the
file trust database can be used in addition to rpmdb.

POLICIES
--------
You might want to look at the fapolicyd.rules file to see what the default
policy looks like. There are 2 policies shipped, known-libs and restrictive.

The restrictive policy is designed with these goals in mind:

1. No bypass of security by executing programs via ld.so.
2. Anything requesting execution must be trusted.
3. Elf binaries, python, and shell scripts are enabled for trusted
   applications/libraries.
4. Other languages are not allowed or must be enabled.

The known-libs policy (default) is designed with these goals in mind:

1. No bypass of security by executing programs via ld.so.
2. Anything requesting execution must be trusted.
3. Any library or interpretted application or module must be trusted.
4. Everything else is not allowed.

EXPERIMENTING
-------------
You can test by starting the daemon from the command line. Before starting
the daemon, cp /usr/bin/ls /usr/bin/my-ls just to setup for testing. When
testing new policy, its highly recommended to use the permissive mode to
make sure nothing bad happens. It really is not too hard to deadlock your
system. Continuing on with the tutorial, as root start the daemon as follows:

```
/usr/sbin/fapolicyd --permissive --debug
```
Then in another window do the following:

1. /usr/lib64/ld-2.29.so /usr/bin/ls
2. my-ls
3. run a python file in your home directory.
4. run a program from /tmp

In permissive + debug mode you will see dec=deny which means
"decision is to deny". But the program will actually be allowed to run.

You can run the daemon from the command line with --debug-deny command
line option. This culls the event notification to only print the denials.
If this is running cleanly, then you can remove the --permissive option
and get true denials. Now retest above steps and see the difference.

DEBUG MODE
----------
In debug mode, you will see events such as this:

```
rule:9 dec=deny_audit perm=execute auid=1001 pid=14137 exe=/usr/bin/bash : file=/home/joe/my-ls ftype=application/x-executable
```

What this is saying is rule 9 made the ultimate Decision that was followed.
The Decision is to deny access and create an audit event. The subject is the
user that logged in as user id 1001. The subject's process id that is trying
to perform an action is 14137. The current executable that the subject is
using is bash. Bash wanted permission to execute /home/joe/my-ls which is the
object. And the object is an ELF executable.

Sometimes you want to list out the rules to see what rule 9 might be. You can
easily do that by running:

```
fapolicyd-cli --list
```

Also, in fapolicyd.conf, there is a configuration option, syslog_format, which
can be modified to output information the way you want to see it. So, if you
think auid in uninteresting you can delete it. If you want to see the device
information for the file being accessed, you can add it. You can also enable
this information to go to syslog by changing the rules to not say audit, but
instead have syslog or log appended to the allow or deny decision.

WRITING RULES
-------------
The rules follow a simple "decision permission subject : object" recipe. For
more information, see the fapolicyd.rules man page.

REPORT
------
On shutdown the daemon will write an object access report to
/var/log/fapolicyd-access.log. The report is from oldest access to newest.
Timestamps are not included because that would be a severe performance hit.
The report gives some basic forensic information about what was being accessed.

PERFORMANCE
-----------
When a program opens a file or calls execve, that thread has to wait for 
fapolicyd to make a decision. To make a decision, fapolicyd has to lookup
information about the process and the file being accessed. Each system call
fapolicyd has to make slows down the system.  

To speed things up, fapolicyd caches everything it looks up so that
subsequent access uses the cache rather than looking things up from
scratch. But the cache is only so big. You are in control of it, though.
You can make both subject and object caches bigger. When the program ends,
it will output some performance statistic like this into
/var/log/fapolicyd-access.log or the screen:

```
Permissive: false
Inter-thread max queue depth 7
Allowed accesses: 116103
Denied accesses: 17
Database max pages: 40960
Database pages in use: 27954 (68%)

Object cache size: 6151
Object slots in use: 6086
Object hits: 110034
Object misses: 34984
Object evictions: 28898

Subject cache size: 1031
Subject slots in use: 1023
Subject hits: 115097
Subject misses: 6770
Subject evictions: 5747
```

In this report, you can see that the internal request queue maxed out at 7.
This means that the daemon had at most 7 threads/processes waiting. This
shows that it got a little backed up but was handling requests pretty quick.
If this number were big, like more than 200, then some action might need to
be taken.

Another statistic worth looking at is the hits to evictions ratio. When a
request has nowhere to put information, it has to evict something to make
room. This is done by a LRU cache which naturally determines what's not
getting used and makes it's memory available for re-use.

In the above statistics, the subject hit ratio was 95%. The object cache was
not quite as lucky. For it, we get a hit ration of 79%. This is still good,
but could be better. This would suggest that for the workload on that system,
the cache could be a little bigger. If the number used for the cache size is
a prime number, you will get less cache churn due to collisions than if it
had a common denominator. Some primes you might consider for cache size are:
1021, 1549, 2039, 4099, 6143, 8191, 10243, 12281, 16381, 20483, etc.

Also, it should be mentioned that the more rules in the policy, the more
rules it will have to iterate over to make a decision. As for the system
performance impact, this is very workload dependent. For a typical desktop
scenario, you won't notice it's running. A system that opens lots of random
files for short periods of time will have more impact.

MEMORY USAGE
------------
Fapolicyd uses lmdb as its trust database. The database has very fast
performance because it uses the kernel virtual memory system to put the
whole database in memory. If the database is sized wrongly, then fapolicyd
will reserve too much memory. Don't worry too much about this. The kernel is
very smart and doesn't actually allocate the memory unless its used. However,
we'd like to get it right sized.

Starting with the 0.9.3 version of fapolicyd, statistics about the database
is output when the program shuts down. On my system, it looks like this:

```
Database max pages: 9728
Database pages in use: 7314 (75%)
```

This also correlates to the following setting in the fapolicyd.conf file:

```
db_max_size = 38
```

This size is in megabytes. So, if you take that and multiply by 1024 * 1024,
we get 39845888. A page of memory is defined as 4096. So, if we divide
max_size by the page size, we get 9728 which matches the setting. Each entry
in the lmdb database is 512 bytes. So, for each 4k page, we can have data on
8 trusted files.

An ideal size for the database is for the statistics to come up aound 75% in
case you decide to install new software some day. The formula is 

```
 (db_max_size x percentage in use) / desired percentage = new db_max_size
```

So, working with example numbers, suppose max_size is 160 and it says it was
68% occupied. That is wasting a little space. Putting the numbers in the
formula, we get  (160 x 68) / 75 = 145.

If you have an embedded system and are not using rpm. But instead use the file
trust source and you have a list of files, then your calculation is very
different. Suppose for the sake of discussion, you have 317 files that are
trusted. We take that number and divide by 8. We'll round that up to 40. Take
that number and multiply by 100 and divide by 75. We come up with 53.33. So,
let's call it 54. This is how many pages is needed. Turning that into real
memory, it's 216K. One megabyte is the smallest allocation, so you would set
```
db_max_size = 1
```

Starting with the 0.9.4 release, the rpm backend filters most files in the
 /usr/share directory. It keeps anything with a with a python extension or
a libexec directory. It also keeps /usr/src/kernel so that Akmod can still
build drivers on a kernel update.

TROUBLESHOOTING
---------------
Whatever you do, DO NOT TRY TO ATTACH WITH PTRACE. Ptrace attachment sends
a SIGSTOP which cannot be blocked. Since your whole system depends on
fapolicyd approving access to glibc and various critical libraries, that
will not happen until SIGCONT is sent. The system can deadlock if the
continue signal is not sent. Using gdb will have the same results. With
that in mind, let's talk about troubleshooting steps...

If you are using deny_audit and you are not getting any audit events, the
fix is to add 1 audit rule. It can be a rule about anything. Watches tend
to be the highest performance, so maybe just add a watch for writes to
etc shadow and restart the audit daemon so the rule gets loaded.

```
-w /etc/shadow -p w
```

When fapolicyd blocks something, it will generate an audit event if the
Decision is deny_audit and it has been compiled with the auditing option.
The audit system must have at least 1 audit rule loaded to create the full
FANOTIFY event. It doesn't matter what rule. To see if you have any denials,
you can run:

```
ausearch --start today -m fanotify --raw | aureport --file --summary

File Summary Report
===========================
total  file
===========================
16  /sbin/ldconfig
1  /home/joe/./my-ls
```

You can also see which executables are involved like this:

```
ausearch --start today -m fanotify -f /sbin/ldconfig --raw | aureport -x --summary

Executable Summary Report
=================================
total  file
=================================
16  /usr/bin/python3.7
```

However, you probably want to know the rule that is blocking it. Unfortunately
the audit system cannot tell you this. What you can do is change the decisions
to deny_log. This will write the event to syslog as well as the audit log. In
syslog, you will have the same output as the debug mode.

The shipped rules expect that everything installed is in the trust database.
If you have installed anything by unzipping it or untarring it, then you need
to add the executables, libraries, and modules to the trust database. See the
MANAGING THE FILE TRUST SOURCE section for instructions on how to do this.

You can ask fapolicyd to include the trust information by adding trust to the
end of the syslog_format configuration option. The things that you need to know
to debug the policy is:

* The rule triggering
* The executable accessing the file
* The object file type
* The trust value

Look at the rule that triggered and see if it makes sense that it triggered. If
the rule is a catch all denial, then check if the file is in the trust db.

MANAGING TRUST
--------------
Fapolicyd use lmdb as a backend database for its trusted software list. You
can find this database in /var/lib/fapolicyd/. This list gets updated
whenever packages are installed by dnf by a dnf plugin. If packages are
installed by rpm instead of dnf, fapolicyd does not get a notification. In
that case, you would also need to tell the daemon that it needs to update
the trust database. This is done by running fapolicyd-cli and passing
along the --update option. Also, if you add or delete files from the file
trust list, fapolicyd.trust, then you will also have to run the fapolicyd-cli
utility.

Lmdb is a very fast database. Normally it works fine. But it does not tolerate
malformed databases. When this happens, it can segfault fapolicyd. The fix
is to delete the database and restart the daemon. It will then rebuild the
database and work as it should. To do this, run the following command:

```
fapolicyd-cli --delete-db
```

MANAGING THE FILE TRUST SOURCE
------------------------------
Starting with 0.9.4, the fapolicyd command line utility can help you manage
the file trust database. For example, suppose you have an application and
its files over in /opt, you can add them all with the following command:

```
fapolicyd-cli --file add /opt/my-app/
```

The commandline utility will walk the directory tree and add all files to
fapolicyd.trust. To do this, it opens each one and calculates the sha256 hash
of the file and write that information to the new entry. Later if you decide
to uninstall that app and you want to cleanup the list, then simply run:

```
fapolicyd-cli --file delete /opt/my-app/
```

The commandline utility will remove all files that match that directory from
fapolicyd.trust. There is also a --file update extension that can update the
size and hash information with what is currently on disk.

Sometimes you want to see what is stored in the combined file and rpm
trust database. In this case you can use the dump command

```
fapolicyd-cli --dump-db
```

which will dump which database the entry came from, path, size, and hash value.

FAQ
---
1) Can this work with other distributions?

Absolutely! There is a backend API that any trust source has to implement.
This API is located in fapolicyd-backend.h. A new backend needs an init, load,
and destroy function. So, someone who knows the debian package database,
for example, could implement a new backend and send a pull request. We are
looking for collaborators.

Also, if the distribution is very small, you can use the file trust database
file. Just add the places where libraries and applications are stored.

2) Can SE Linux or AppArmor do this instead?

SE Linux is modeling how an application behaves. It is not concerned about
where the application came from or whether its known to the system. Basically,
anything in /bin gets bin_t type by default which is not a very restrive label.
MAC systems serve a different purpose. Fapolicyd by design cares solely about
if this is a known application/library. These are complimentary security
subsystems. There is more information about application whitelisting use cases
at the following NIST website:

https://www.nist.gov/publications/guide-application-whitelisting

3) Does the daemon check file integrity?

Version 0.9.5 and later supports 3 modes of integrity checking. The first is
based on file size. In this mode, fapolicyd will take the size information
from the trust db and compare it with the measured file size. This test
incurs no overhead since the file size is collected when establishing
uniqueness for caching purposes. It is intended to detect accidental overwrites
as opposed to malicious activity where the attacker can make the file size
match.

The second mode is based on using IMA to calculate sha256 hashes and make them
available through extended attributes. This incurs only the overhead of calling
fgetxattr which is fast since there is no path name resolution. The file system
must support i_version. For XFS, this is enabled by default. For other file
systems, this means you need to add the i_version mount option. In either
case, IMA must be setup appropriately.

The third mode is where fapolicyd calculates a SHA256 hash of the file itself
and compares that with what is stored in the trust db.

4) This is only looking at location. Can't this be defeated by simply moving
the files to another location?

Yes, this is checking to see if this is a known file. Known files have a known
location. The shipped policy prevents execution from /tmp, /var/tmp, and $HOME.
So, where could an unprivileged user move the file to? And if you are thinking,
I have root permissions, I'll move the file somewhere else. OK, if you are
root, you can change the rules or simply turn off the deamon, too. So, this
is not designed to prevent root from doing things. Also, moving a file means
it's no longer "known" and will be blocked from executing. And if something
were moved to overwrite it, then the hash is no longer the same.

5) How do you prevent race conditions on startup? Can something execute before
the daemon takes control?

One of the design goals is to take control before users can login. Users are
the main problem being addressed. They can pip install apps to the home dir
or do other things an admin may wish to prevent. Only root can install things
that run before login. And again, root can change the rules or turn off the
daemon.

Another design goal is to prevent malicious apps from running. Suppose someone
guesses your password and they login to your account. Perhaps they wish to
ransomware your home dir. The app they try to run is not known to the system
and will be stopped. Or suppose there is an exploitable service on your system.
The attacker is lucky enough to pop a shell. Now they want to download
privilege escalation tools or perhaps an LD_PRELOAD key logger. Since neither
of these are in the trust database, they won't be allowed to run.

This is really about stopping escalation or exploitation before the attacker
can gain any advantage to install root kits. If we can do that, UEFI secure
boot can make sure no other problems exist during boot.

Wrt to the second question being asked, fapolicyd starts very early in the
boot process and startup is very fast. It's running well before other login
daemons.

NOTES
-----
* It's highly recommended to run in permissive mode while you are testing the
daemon's policy.

* Stracing the daemon can deadlock the system.

* About shell script restrictions...there's not much difference between
running a script or someone typing things in by hand. The aim at this
point is to check that any program it calls meets the policy.

* If for some reason rpm database errors are detected, you may need to do
the following:

```
1. db_verify /var/lib/rpm/Packages
if OK, then
2. rm -f /var/lib/rpm/__db*
3. rpm --rebuilddb
```

[1] - https://git.kernel.org/pub/scm/linux/kernel/git/jack/linux-fs.git/commit/?id=66917a3130f218dcef9eeab4fd11a71cd00cd7c9

