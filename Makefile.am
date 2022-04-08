ACLOCAL_AMFLAGS	= -I m4

SUBDIRS = 	src	\
		include	\
		files	\
		doc	\
		examples
if HAVE_PYTHON
SUBDIRS += py
endif

EXTRA_DIST =	tests	\
		files

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnftables.pc
