EXTRA_DIST = \
	fapolicyd.service.in \
	fapolicyd.conf \
	fapolicyd-filter.conf \
	fapolicyd.trust \
	fapolicyd.sysusers \
	fapolicyd-tmpfiles.conf \
	fapolicyd-magic \
	fapolicyd.bash_completion \
	fagenrules

fapolicyddir = $(sysconfdir)/fapolicyd
fapolicyrulesdir = $(fapolicyddir)/rules.d
fapolicytrustdir = $(fapolicyddir)/trust.d

dist_fapolicyd_DATA = \
	fapolicyd.conf \
	fapolicyd-filter.conf \
	fapolicyd.trust

systemdservicedir = $(systemdsystemunitdir)
nodist_systemdservice_DATA = fapolicyd.service

tmpfilesdir = @tmpfilesdir@
sysusersdir = @sysusersdir@

sbin_SCRIPTS = fagenrules

completiondir = $(sysconfdir)/bash_completion.d/
dist_completion_DATA = fapolicyd.bash_completion

MAGIC = fapolicyd-magic.mgc
pkgdata_DATA = ${MAGIC} 
CLEANFILES = ${MAGIC} fapolicyd.service

${MAGIC}: $(EXTRA_DIST)
	file -C -m ${top_srcdir}/init/fapolicyd-magic

install-data-hook:
	$(MKDIR_P) "$(DESTDIR)$(fapolicyrulesdir)"
	$(MKDIR_P) "$(DESTDIR)$(fapolicytrustdir)"
	$(MKDIR_P) "$(DESTDIR)$(tmpfilesdir)"
	$(INSTALL_DATA) "$(srcdir)/fapolicyd-tmpfiles.conf" \
		"$(DESTDIR)$(tmpfilesdir)/fapolicyd.conf"
	$(MKDIR_P) "$(DESTDIR)$(sysusersdir)"
	$(INSTALL_DATA) "$(srcdir)/fapolicyd.sysusers" \
		"$(DESTDIR)$(sysusersdir)/fapolicyd.conf"

uninstall-hook:
	rm -f "$(DESTDIR)$(tmpfilesdir)/fapolicyd.conf"
	rm -f "$(DESTDIR)$(sysusersdir)/fapolicyd.conf"
