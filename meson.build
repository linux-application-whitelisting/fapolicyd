project(
    'fapolicyd',
    'c',
    version: '1.4.3',
    default_options: [
        'c_std=gnu11',
        'warning_level=2',
        'buildtype=debugoptimized',
        'b_pie=true',
    ],
    meson_version: '>= 1.1.0',  # meson.options
)

fs = import('fs')

cc = meson.get_compiler('c')

# Configuration
conf_data = configuration_data()
conf_data.set_quoted('VERSION', meson.project_version())
conf_data.set('_GNU_SOURCE', 1)
conf_data.set('PIE', 1)
conf_data.set('STDC_HEADERS', 1)

if get_option('debug')
    conf_data.set('DEBUG', 1)
endif

# Standard headers that autotools checks for
check_std_headers = [
    'dlfcn.h',
    'inttypes.h',
    'minix/config.h',
    'stdint.h',
    'stdio.h',
    'stdlib.h',
    'strings.h',
    'string.h',
    'sys/stat.h',
    'sys/types.h',
    'unistd.h',
    'wchar.h',
]

foreach h : check_std_headers
    if cc.has_header(h)
        conf_data.set('HAVE_' + h.to_upper().underscorify(), 1)
    endif
endforeach

# Check for headers
check_headers = ['sys/fanotify.h', 'uthash.h', 'linux/fanotify.h']

foreach h : check_headers
    if not cc.has_header(h)
        error('Header ' + h + ' not found')
    endif
endforeach

# Check for functions
check_funcs = ['fexecve', 'gettid', 'mallinfo2']

foreach f : check_funcs
    if cc.has_function(f)
        conf_data.set('HAVE_' + f.to_upper(), 1)
    endif
endforeach

# Check for struct members
if cc.has_member(
    'struct fanotify_response_info_audit_rule',
    'rule_number',
    prefix: '#include <linux/fanotify.h>',
)
    conf_data.set('FAN_AUDIT_RULE_NUM', 1)
endif

# Check for declarations
check_decls = [
    ['FAN_AUDIT', 'linux/fanotify.h'],
    ['FAN_OPEN_EXEC_PERM', 'linux/fanotify.h'],
    ['FAN_MARK_FILESYSTEM', 'linux/fanotify.h'],
]

foreach d : check_decls
    if cc.has_header_symbol(d[1], d[0])
        conf_data.set('HAVE_DECL_' + d[0], 1)
    endif
    # Special check for FAN_OPEN_EXEC_PERM as it is required
    if d[0] == 'FAN_OPEN_EXEC_PERM' and not cc.has_header_symbol(d[1], d[0])
        error(
            d[0] + ' is not defined in ' + d[1] + '. It is required for the kernel to support it',
        )
    endif
endforeach

# Dependencies

deps = []
deps_summary = {}

foreach dep : [
    'libcap-ng',
    'libcrypto',
    'lmdb',
    'libmagic',
    'libseccomp',
    'libudev',
    'threads',
]
    d = dependency(dep, required: true)
    deps += d
    deps_summary += {dep: d}
endforeach

# Options
if get_option('audit')
    conf_data.set('USE_AUDIT', 1)
endif

librpm = dependency('rpm', required: get_option('rpm'))

if librpm.found()
    deps += [librpm]
    conf_data.set('USE_RPM', 1)
    conf_data.set('HAVE_LIBRPM', 1)
endif


libdpkg = dependency('libdpkg', required: get_option('deb'))

if libdpkg.found()
    deps += libdpkg
    conf_data.set('USE_DEB', 1)
    conf_data.set('LIBDPKG_VOLATILE_API', 1)
endif

use_ebuild = get_option('ebuild').allowed()  # no dependency to check for found
if use_ebuild
    conf_data.set('USE_EBUILD', 1)
endif

if libdpkg.found() or use_ebuild
    conf_data.set('NEED_MD5', 1)
endif

ld_so_path = get_option('ld_so_path')

if ld_so_path != ''
    message('Using user-specified dynamic linker: ' + ld_so_path)

else

    message('Auto-detecting dynamic linker...')

    python = import('python').find_installation()
    bash = find_program('bash')

    elf_tool = find_program('readelf', required: false)
    tool_mode = 'readelf'

    if not elf_tool.found()
        elf_tool = find_program('objdump', required: false)
        tool_mode = 'objdump'
    endif

    if not elf_tool.found()
        error(
            'Found neither readelf nor objdump. Please set -Dsystem_ld_so=/path/to/loader manually.',
        )
    endif

    get_interp_script = '''
import sys, subprocess

tool_bin = sys.argv[1]
mode = sys.argv[2]
target_bin = sys.argv[3]

try:
    if mode == 'readelf':
        output = subprocess.check_output([tool_bin, '-p', '.interp', target_bin], text=True)
        # Extract the string from the dump format
        for line in output.split('\\n'):
            if ']' in line and line.strip() and not 'Hex' in line:
                # Get the ASCII part after the closing bracket
                part = line.split(']')[1].strip()
                if part:
                    print(part.rstrip('\\x00'), end='')
                    sys.exit(0)
        sys.exit(1)
    elif mode == 'objdump':
        output = subprocess.check_output([tool_bin, '-s', '-j', '.interp', target_bin], text=True)
        hex_data = []
        for line in output.split('\\n'):
            if line.strip().startswith('0'):
                parts = line.split()
                # First part is address, last part is ASCII, middle are hex
                hex_parts = parts[1:-1] if len(parts) > 2 else parts[1:]
                hex_data.extend(hex_parts)

        if hex_data:
            hex_string = ''.join(hex_data)
            result = bytes.fromhex(hex_string).decode('ascii', errors='ignore').rstrip('\\x00')
            print(result, end='')
        else:
            sys.exit(1)
except Exception:
    sys.exit(1)
'''

    interp_cmd = run_command(
        python,
        '-c',
        get_interp_script,
        elf_tool.full_path(),
        tool_mode,
        bash.full_path(),
        check: true,
    )

    ld_so_path = interp_cmd.stdout()

    if not fs.exists(ld_so_path) or ld_so_path == ''
        error('Computed dynamic linker does not exist: ' + ld_so_path)
    endif

    message('Auto-detected dynamic linker (' + tool_mode + '): ' + ld_so_path)
endif

conf_data.set_quoted('SYSTEM_LD_SO', ld_so_path)

# Compiler flags
project_args = [
    '-D_GNU_SOURCE',
    '-Wshadow',
    '-Wundef',
    '-Wno-unused-result',
    '-Wno-unused-parameter',
]

if libdpkg.found()
    project_args += '-DLIBDPKG_VOLATILE_API'
endif

add_project_arguments(project_args, language: 'c')

# Generate config.h
configure_file(output: 'config.h', configuration: conf_data)

# Include directories
inc = include_directories('.', 'src', 'src/library')

# Source files
lib_sources = files(
    'src/library/attr-sets.c',
    'src/library/avl.c',
    'src/library/backend-manager.c',
    'src/library/daemon-config.c',
    'src/library/database.c',
    'src/library/escape.c',
    'src/library/event.c',
    'src/library/fd-fgets.c',
    'src/library/file-backend.c',
    'src/library/file.c',
    'src/library/filter.c',
    'src/library/llist.c',
    'src/library/lru.c',
    'src/library/message.c',
    'src/library/object-attr.c',
    'src/library/object.c',
    'src/library/policy.c',
    'src/library/process.c',
    'src/library/queue.c',
    'src/library/rules.c',
    'src/library/stack.c',
    'src/library/string-util.c',
    'src/library/subject-attr.c',
    'src/library/subject.c',
    'src/library/trust-file.c',
)

if librpm.found()
    lib_sources += files('src/library/rpm-backend.c')
endif

if libdpkg.found() or use_ebuild
    lib_sources += files('src/library/md5-backend.c')
endif

if libdpkg.found()
    lib_sources += files('src/library/deb-backend.c')
endif

if use_ebuild
    lib_sources += files('src/library/ebuild-backend.c')
endif

# Library
libfapolicyd = static_library(
    'fapolicyd',
    lib_sources,
    include_directories: inc,
    dependencies: deps,
)

# Executables
executable(
    'fapolicyd',
    ['src/daemon/fapolicyd.c', 'src/daemon/mounts.c', 'src/daemon/notify.c'],
    include_directories: inc,
    link_with: libfapolicyd,
    dependencies: deps,
    install: true,
    install_dir: get_option('sbindir'),
)

executable(
    'fapolicyd-cli',
    ['src/cli/fapolicyd-cli.c', 'src/cli/file-cli.c'],
    include_directories: inc,
    link_with: libfapolicyd,
    dependencies: deps,
    install: true,
    install_dir: get_option('sbindir'),
)

if librpm.found()
    executable(
        'fapolicyd-rpm-loader',
        ['src/handler/fapolicyd-rpm-loader.c'],
        include_directories: inc,
        link_with: libfapolicyd,
        dependencies: deps,
        install: true,
        install_dir: get_option('bindir'),
    )
endif

# Man pages
man_pages = files(
    'doc/fagenrules.8',
    'doc/fapolicyd-cli.8',
    'doc/fapolicyd-filter.conf.5',
    'doc/fapolicyd.8',
    'doc/fapolicyd.conf.5',
    'doc/fapolicyd.rules.5',
    'doc/fapolicyd.trust.5',
    'doc/rpm-filter.conf.5',
)

install_man(man_pages)

# Rules
install_subdir(
    'rules.d',
    install_dir: get_option('sysconfdir') / 'fapolicyd',
    strip_directory: true,
    exclude_files: ['Makefile', 'Makefile.am', 'Makefile.in'],
)

# Init scripts
install_data(
    'init/systemd/fapolicyd.service',
    install_dir: get_option('prefix') / 'lib/systemd/system',
)


install_data(
    'init/fapolicyd-tmpfiles.conf',
    install_dir: get_option('prefix') / 'lib/tmpfiles.d',
    rename: 'fapolicyd.conf',
)

install_data(
    'init/openrc/init.d/fapolicyd',
    install_dir: '/etc/init.d',
    install_mode: 'rwxr-xr-x',
)
install_data('init/openrc/conf.d/fapolicyd', install_dir: '/etc/conf.d')


# Config files
install_data(
    'init/data/fapolicyd.conf',
    install_dir: get_option('sysconfdir') / 'fapolicyd',
)
install_data(
    'init/data/fapolicyd-filter.conf',
    install_dir: get_option('sysconfdir') / 'fapolicyd',
)
install_data(
    'init/data/fapolicyd.trust',
    install_dir: get_option('sysconfdir') / 'fapolicyd',
)

# Magic file compilation
file_prog = find_program('file', required: true)
magic_src = files('init/fapolicyd-magic')

custom_target(
    'fapolicyd-magic.mgc',
    input: magic_src,
    output: 'fapolicyd-magic.mgc',
    command: [file_prog, '-C', '-m', '@INPUT@'],
    install: true,
    install_dir: get_option('datadir') / 'fapolicyd',
)

# Scripts
install_data(
    'init/fagenrules',
    install_dir: get_option('sbindir'),
    install_mode: 'rwxr-xr-x',
)

install_data(
    'init/fapolicyd.bash_completion',
    install_dir: get_option('sysconfdir') / 'bash_completion.d',
)

# Tests
test_inc = include_directories('src/library')

# Standalone tests
standalone_tests = [
    ['avl_test', ['src/tests/avl_test.c', 'src/library/avl.c']],
    ['trustdb_format_test', ['src/tests/trustdb_format_test.c']],
]

foreach t : standalone_tests
    exe = executable(
        t[0],
        t[1],
        include_directories: test_inc,
        dependencies: deps,
    )
    test(t[0], exe)
endforeach

# Tests linking libfapolicyd
linked_tests = [
    ['gid_proc_test', ['src/tests/gid_proc_test.c']],
    ['uid_proc_test', ['src/tests/uid_proc_test.c']],
    ['escape_test', ['src/tests/escape_test.c']],
    ['attr_sets_test', ['src/tests/attr_sets_test.c']],
    ['elf_file_test', ['src/tests/elf_file_test.c']],
    ['fd_fgets_test', ['src/tests/fd_fgets_test.c']],
]

if use_ebuild
    linked_tests += [['ebuild_test', ['src/tests/ebuild_test.c']]]
endif

if libdpkg.found()
    linked_tests += [['deb_test', ['src/tests/deb_test.c']]]
endif

foreach t : linked_tests
    exe = executable(
        t[0],
        t[1],
        include_directories: test_inc,
        link_with: libfapolicyd,
        dependencies: deps,
    )
    test(
        t[0],
        exe,
        env: {'srcdir': meson.current_source_dir() / 'src/tests'},
    )
endforeach

# rules_test needs special define
rules_test_exe = executable(
    'rules_test',
    ['src/tests/rules_test.c'],
    include_directories: test_inc,
    link_with: libfapolicyd,
    dependencies: deps,
    c_args: '-DTEST_BASE="' + meson.current_source_dir() + '"',
)
test('rules_test', rules_test_exe)

event_test_exe = executable(
    'event_test',
    ['src/tests/event_test.c'],
    include_directories: test_inc,
    link_with: libfapolicyd,
    dependencies: deps,
)
test('event_test', event_test_exe)

# filter_test needs special define
filter_test_exe = executable(
    'filter_test',
    ['src/tests/filter_test.c'],
    include_directories: test_inc,
    link_with: libfapolicyd,
    dependencies: deps,
    c_args: '-DTEST_BASE="' + meson.current_source_dir() + '"',
)
test('filter_test', filter_test_exe)

# file_filter_test needs special define
file_filter_test_exe = executable(
    'file_filter_test',
    ['src/tests/file_filter_test.c'],
    include_directories: test_inc,
    link_with: libfapolicyd,
    dependencies: deps,
    c_args: '-DTEST_BASE="' + meson.current_source_dir() + '"',
)
test('file_filter_test', file_filter_test_exe)

summary(
    {
        'prefix': get_option('prefix'),
        'bindir': get_option('bindir'),
        'datadir': get_option('datadir'),
        'libdir': get_option('libdir'),
        'libexecdir': get_option('libexecdir'),
    },
    section: 'Directories',
)

environment_summary = {
    'Build': build_machine.system(),
    'Build CPU Family': build_machine.cpu_family(),
    'Host CPU Family': host_machine.cpu_family(),
    'Cross-compiling': meson.is_cross_build(),
    'Build Endianness': build_machine.endian(),
    'Host Endianness': host_machine.endian(),
    'Target': host_machine.system(),
    'C Compiler': cc.get_id(),
    'C Compiler Version': cc.version(),
    'Linker': cc.get_linker_id(),
}

summary(
    {
        'Audit support': get_option('audit'),
        'RPM backend': librpm.found(),
        'Debian backend': libdpkg.found(),
        'Ebuild backend': use_ebuild,
        'ld.so path': ld_so_path,
    },
    section: 'Configuration',
    bool_yn: true,
)

if librpm.found()
    deps_summary += {'rpm': librpm}
endif

if libdpkg.found()
    deps_summary += {'libdpkg': libdpkg}
endif

summary(deps_summary, section: 'Dependencies', bool_yn: true)
