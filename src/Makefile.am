AUTOMAKE_OPTIONS = -Wno-override
lib_LTLIBRARIES = mod_repsheet.la
mod_repsheet_la_SOURCES = mod_repsheet.c
mod_repsheet_la_LDFLAGS = -module -lhiredis -lrepsheet
AM_CFLAGS = `@LOCAL_APACHE_BIN_DIR@apr-1-config --cflags`
AM_CPPFLAGS = -I@APACHE_INCLUDE_DIR@ `@LOCAL_APACHE_BIN_DIR@apr-1-config --cppflags --includes`

install:
	@APXS@ -i -a mod_repsheet.la
