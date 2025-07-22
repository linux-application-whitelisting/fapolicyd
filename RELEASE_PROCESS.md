# fapolicyd Release Process

1. **Clean the repository**

   ```bash
   git clean -xfd
   ```

2. **Bootstrap and build**

   ```bash
   ./autogen.sh
   ./configure --with-audit --with-rpm --disable-shared
   make
   ```

3. **Run the test suite**

   ```bash
   make check
   ```

4. **Build with Address Sanitizer**

   Reconfigure with `--with-asan`, rebuild, and run both the daemon and
   command-line client to ensure there are no ASAN failures.

   ```bash
   ./configure --with-audit --with-rpm --disable-shared --with-asan
   make
   sudo ./src/fapolicyd --debug-deny
   sudo ./src/fapolicyd-cli --dump-db
   ```

5. **Update version numbers**
   - `configure.ac` line 2
   - `fapolicyd.spec` line 12
   - Document the changes in `ChangeLog`.

6. **Create the source tarball**

   ```bash
   ./autogen.sh
   ./configure --with-audit --with-rpm --disable-shared
   make dist
   ```

7. **Tag the release**

   ```bash
   git tag -s -m "fapolicyd-X.Y.Z" vX.Y.Z
   git push origin vX.Y.Z
   ```

8. **Sign the tarball**

   ```bash
   sha256sum fapolicyd-X.Y.Z.tar.gz > fapolicyd-X.Y.Z.tar.gz.sum
   gpg --armor --detach-sign fapolicyd-X.Y.Z.tar.gz
   gpg --clearsign fapolicyd-X.Y.Z.tar.gz.sum
   ```

9. **Publish on GitHub**

   Create a new release with the tag, include notes from `ChangeLog`, and
   upload the following files:

   - `fapolicyd-X.Y.Z.tar.gz`
   - `fapolicyd-X.Y.Z.tar.gz.asc`
   - `fapolicyd-X.Y.Z.tar.gz.sum`
   - `fapolicyd-X.Y.Z.tar.gz.sum.asc`
