EXTRA_DIST = \
	fapolicyd.service.in \
	fapolicyd.conf \
	fapolicyd-filter.conf \
	fapolicyd.trust \
	fapolicyd-tmpfiles.conf.in \
	fapolicyd-magic \
	fapolicyd.bash_completion \
	fagenrules.in

fapolicyddir = $(sysconfdir)/fapolicyd

dist_fapolicyd_DATA = \
	fapolicyd.conf \
	fapolicyd-filter.conf \
	fapolicyd.trust

systemdservicedir = $(systemdsystemunitdir)
systemdservice_DATA = fapolicyd.service

sbin_SCRIPTS = fagenrules

fagenrules: fagenrules.in Makefile
	$(SED) -e 's|[@]sysconfdir[@]|$(sysconfdir)|g' $< > $@
	chmod 755 $@

fapolicyd-tmpfiles.conf: fapolicyd-tmpfiles.conf.in Makefile
	$(SED) -e 's|[@]runstatedir[@]|$(runstatedir)|g' -e 's|[@]localstatedir[@]|$(localstatedir)|g' -e 's|[@]sysconfdir[@]|$(sysconfdir)|g' $< > $@

fapolicyd.service: fapolicyd.service.in Makefile
	$(SED) -e 's|[@]runstatedir[@]|$(runstatedir)|g' -e 's|[@]sbindir[@]|$(sbindir)|g' $< > $@

tmpfilesdir = $(prefix)/lib/tmpfiles.d
tmpfiles_DATA = fapolicyd-tmpfiles.conf

completiondir = $(sysconfdir)/bash_completion.d/
dist_completion_DATA = fapolicyd.bash_completion

MAGIC = fapolicyd-magic.mgc
pkgdata_DATA = ${MAGIC} 
CLEANFILES = ${MAGIC} fagenrules fapolicyd.service fapolicyd-tmpfiles.conf

${MAGIC}: $(EXTRA_DIST)
	file -C -m ${top_srcdir}/init/fapolicyd-magic
