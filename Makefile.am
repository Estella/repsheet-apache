ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src

local:
	make && build/apache24/bin/apxs -i -a src/mod_repsheet.la
