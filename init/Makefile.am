EXTRA_DIST = \
	fapolicyd.service \
	fapolicyd.conf \
	rpm-filter.conf \
	fapolicyd.trust \
	fapolicyd-tmpfiles.conf \
	fapolicyd-magic \
	fapolicyd.bash_completion \
	fagenrules

fapolicyddir = $(sysconfdir)/fapolicyd

dist_fapolicyd_DATA = \
	fapolicyd.conf \
	rpm-filter.conf \
	fapolicyd.trust

systemdservicedir = $(systemdsystemunitdir)
dist_systemdservice_DATA = fapolicyd.service

sbin_SCRIPTS = fagenrules

completiondir = $(sysconfdir)/bash_completion.d/
dist_completion_DATA = fapolicyd.bash_completion

MAGIC = fapolicyd-magic.mgc
pkgdata_DATA = ${MAGIC} 
CLEANFILES = ${MAGIC}

${MAGIC}: $(EXTRA_DIST)
	file -C -m ${top_srcdir}/init/fapolicyd-magic
