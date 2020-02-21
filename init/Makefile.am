EXTRA_DIST = \
	fapolicyd.rules \
	fapolicyd.service \
	fapolicyd.conf \
	fapolicyd.trust \
	fapolicyd-tmpfiles.conf \
	fapolicyd-magic

fapolicyddir = $(sysconfdir)/fapolicyd

dist_fapolicyd_DATA = \
	fapolicyd.rules \
	fapolicyd.conf \
	fapolicyd.trust

systemdservicedir = $(systemdsystemunitdir)
dist_systemdservice_DATA = fapolicyd.service

MAGIC = fapolicyd-magic.mgc
pkgdata_DATA = ${MAGIC}
CLEANFILES = ${MAGIC}

${MAGIC}: $(EXTRA_DIST)
	file -C -m ${top_srcdir}/init/fapolicyd-magic
