
SUBDIRS = src init doc rules.d

TEST_FIXTURES = \
src/tests/fixtures/filter-minimal.conf \
src/tests/fixtures/filter-cases.txt \
src/tests/fixtures/broken-filter.conf \
init/fapolicyd-filter.conf

EXTRA_DIST = ChangeLog AUTHORS NEWS README.md INSTALL fapolicyd.spec \
dnf/fapolicyd-dnf-plugin.py autogen.sh \
$(TEST_FIXTURES)

dist_check_DATA = $(TEST_FIXTURES)

clean-generic:
	rm -rf autom4te*.cache
	rm -f *.rej *.orig *.lang *.list
