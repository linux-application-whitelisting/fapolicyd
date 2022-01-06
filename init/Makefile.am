EXTRA_DIST = \
	fapolicyd.service \
	fapolicyd.conf \
	fapolicyd.trust \
	fapolicyd-tmpfiles.conf \
	fapolicyd-magic \
	fagenrules

fapolicyddir = $(sysconfdir)/fapolicyd

dist_fapolicyd_DATA = \
	fapolicyd.conf \
	fapolicyd.trust

systemdservicedir = $(systemdsystemunitdir)
dist_systemdservice_DATA = fapolicyd.service

sbin_SCRIPTS = fagenrules

MAGIC = fapolicyd-magic.mgc
pkgdata_DATA = ${MAGIC} 
CLEANFILES = ${MAGIC}

${MAGIC}: $(EXTRA_DIST)
	file -C -m ${top_srcdir}/init/fapolicyd-magic
