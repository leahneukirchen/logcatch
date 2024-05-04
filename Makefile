ALL=logcatch

CFLAGS?=-g -O2 -Wall -Wno-switch -Wextra -Wwrite-strings
LDLIBS=-lcap

DESTDIR=
PREFIX?=/usr/local
BINDIR=$(PREFIX)/bin
MANDIR=$(PREFIX)/share/man

all: $(ALL)

README: logcatch.1
	mandoc -Tutf8 $^ | col -bx >$@

cap: $(ALL)
	sudo setcap cap_sys_admin,cap_setpcap+ep logcatch

clean: FRC
	rm -f $(ALL)

install: FRC all
	mkdir -p $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man1
	install -m0755 $(ALL) $(DESTDIR)$(BINDIR)
	install -m0644 $(ALL:=.1) $(DESTDIR)$(MANDIR)/man1

FRC:
