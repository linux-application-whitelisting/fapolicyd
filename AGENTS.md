# Repository Guidelines

This project contains the code for the File Access Policy Deamon
(fapolicyd). The repository uses autotools and has optional self-tests.  
Follow the instructions below when making changes.

## Building

1. Bootstrap and configure the build. The README shows an example:

   ```
   cd fapolicyd
   autoreconf -f --install
   ./configure --with-audit --with-rpm --with-deb --disable-shared
   make
   ```

2. Tests can be run with `make check` as described in INSTALL:

   ```
   2. Type 'make' to compile the package.

   3. Optionally, type 'make check' to run any self-tests that come with
      the package, generally using the just-built uninstalled binaries.

3. Installation (`make install`) is typically performed only after
successful tests.

## Project Structure for Navigation

- `/src`: This is where the code that makes up fapolicyd and fapolicy-cli are located
  - `/library`: This is where the common code between fapolicyd and the cli app is located
  - `/daemon`: This is where the daemon code for fapolicyd is located
  - `/cli`: This is where we find the code for the command line helper application.
- `/dnf`: This holds the code for fapolicyd-dnf-plugin.py
- `/deb`: This holds information about building for Debian
- `/init`: This holds the code related to initializing the daemon and loading rules
- `/docs`: This holds all of the man pages
- `/rules.d`: This holds access control rules

## Code Style

Contributions should follow the Linux Kernel coding style:

```
So, if you would like to test it and report issues or even contribute code
feel free to do so. But please discuss the contribution first to ensure
that its acceptable. This project uses the Linux Kernel Style Guideline.
Please follow it if you wish to contribute.
```

In practice this means:

- Indent with tabs (8 spaces per tab).
- Keep lines within ~80 columns.
- Place braces and other formatting as in the kernel style. However, if the
  basic block is a 1 liner, do not use curly braces for it.
- Add a comment before any new function describing it, input variables, and
  return codes.
- Comments within a function may be C++ style.
- Do not do any whitespace adustment of existing code.
- Keep existing function and variable names.

## Commit Messages

- Use a concise one-line summary followed by a blank line and additional
  details if needed (similar to existing commits).

## Special Files

The `rules.d` directory contains groups of access control rules intended for
`fagenrules` and should remain organized as documented:

```
This group of rules are meant to be used with the fagenrules program.
The fagenrules program expects rules to be located in /etc/fapolicy/rules.d/
The rules will get processed in a specific order based on their natural
sort order. To make things easier to use, the files in this directory are
organized into groups with the following meanings:

 10 - macros
 20 - loop holes
 30 - patterns
 40 - ELF rules
 50 - user/group access rules
 60 - application access rules
 70 - language rules
 80 - trusted execute
 90 - general open access to documents
```

When editing rule files, keep them in the correct group and preserve the
intended ordering.

## Summary

- Build with `autoreconf`, `configure`, and `make`.
- Run `make check` to execute the self-tests.
- Follow Linux Kernel coding style (tabs, 80 columns).
- Keep commit messages short and descriptive.
- Always add comments to explain new code.
- Maintain rule file organization as described in `rules.d/README-rules`.

These guidelines should help future contributors and automated tools
work consistently within the fapolicyd repository.

