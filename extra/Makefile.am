EXTRA_DIST = \
	data/fapolicyd-filter.conf \
	data/fapolicyd.conf \
	data/fapolicyd.trust \
	openrc/conf.d/fapolicyd \
	openrc/init.d/fapolicyd \
	systemd/fapolicyd.service \
	fapolicyd-tmpfiles.conf \
	fapolicyd-magic \
	fapolicyd.bash_completion \
	fagenrules

fapolicyddir = $(sysconfdir)/fapolicyd

dist_fapolicyd_DATA = \
	data/fapolicyd.conf \
	data/fapolicyd-filter.conf \
	data/fapolicyd.trust

systemdservicedir = $(systemdsystemunitdir)
dist_systemdservice_DATA = systemd/fapolicyd.service

openrcinitdir = $(sysconfdir)/init.d
dist_openrcinit_DATA = openrc/init.d/fapolicyd
openrcconfdir = $(sysconfdir)/conf.d
dist_openrcconf_DATA = openrc/conf.d/fapolicyd

sbin_SCRIPTS = fagenrules

completiondir = $(sysconfdir)/bash_completion.d/
dist_completion_DATA = fapolicyd.bash_completion

MAGIC = fapolicyd-magic.mgc
pkgdata_DATA = ${MAGIC}
CLEANFILES = ${MAGIC}

${MAGIC}: $(EXTRA_DIST)
	file -C -m ${top_srcdir}/extra/fapolicyd-magic
