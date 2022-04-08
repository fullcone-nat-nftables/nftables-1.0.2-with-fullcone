if BUILD_MAN
man_MANS = nft.8 libnftables-json.5 libnftables.3

A2X_OPTS_MANPAGE = -L --doctype manpage --format manpage -D ${builddir}

ASCIIDOC_MAIN = nft.txt
ASCIIDOC_INCLUDES = \
       data-types.txt \
       payload-expression.txt \
       primary-expression.txt \
       stateful-objects.txt \
       statements.txt
ASCIIDOCS = ${ASCIIDOC_MAIN} ${ASCIIDOC_INCLUDES}

EXTRA_DIST = ${ASCIIDOCS} ${man_MANS} libnftables-json.adoc libnftables.adoc

CLEANFILES = \
	*~

nft.8: ${ASCIIDOCS}
	${AM_V_GEN}${A2X} ${A2X_OPTS_MANPAGE} $<

.adoc.3:
	${AM_V_GEN}${A2X} ${A2X_OPTS_MANPAGE} $<

.adoc.5:
	${AM_V_GEN}${A2X} ${A2X_OPTS_MANPAGE} $<

CLEANFILES += ${man_MANS}
endif
