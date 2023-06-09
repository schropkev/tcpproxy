##
##  tcpproxy
##
##  tcpproxy is a simple tcp connection proxy which combines the
##  features of rinetd and 6tunnel. tcpproxy supports IPv4 and
##  IPv6 and also supports connections from IPv6 to IPv4
##  endpoints and vice versa.
##
##
##  Copyright (C) 2010-2015 Christian Pointner <equinox@spreadspace.org>
##
##  This file is part of tcpproxy.
##
##  tcpproxy is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation, either version 3 of the License, or
##  any later version.
##
##  tcpproxy is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with tcpproxy. If not, see <http://www.gnu.org/licenses/>.
##

ifneq ($(MAKECMDGOALS),distclean)
include include.mk
endif

EXECUTABLE := tcpproxy

C_OBJS := log.o \
          options.o \
          cfg_parser.o \
          slist.o \
          string_list.o \
          sig_handler.o \
          tcp.o \
          listener.o \
          clients.o \
          tcpproxy.o

C_SRCS := $(C_OBJS:%.o=%.c)

.PHONY: clean cleanall distclean manpage install install-bin install-etc install-man uninstall remove purge

all: $(EXECUTABLE)

cfg_parser.c: cfg_parser.rl
	$(RAGEL) -C -G2 -o $@ $<

cfg_parser.dot: cfg_parser.rl
	$(RAGEL) -V -p -o $@ $<

cfg_parser.png: cfg_parser.dot
	@dot -Tpng $< > $@

%.d: %.c
	@set -e; rm -f $@; \
  $(CC) -MM $(CFLAGS) $< > $@.$$$$; \
  sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
  rm -f $@.$$$$; echo '(re)building $@'

ifneq ($(MAKECMDGOALS),distclean)
-include $(C_SRCS:%.c=%.d)
endif

$(EXECUTABLE): $(C_OBJS)
	$(CC) $(C_OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

strip: $(EXECUTABLE)
	$(STRIP) -s $(EXECUTABLE)


distclean: cleanall
	find . -name *.o -exec rm -f {} \;
	find . -name "*.\~*" -exec rm -rf {} \;
	rm -f include.mk
	rm -f config.h

clean:
	rm -f *.o
	rm -f *.d
	rm -f *.d.*
	rm -f cfg_parser.c
	rm -f cfg_parser.png cfg_parser.dot
	rm -f $(EXECUTABLE)

cleanall: clean
	$(MAKE) --directory="../doc/" clean

manpage:
	$(MAKE) --directory="../doc/" manpage


INSTALL_TARGETS := install-bin install-systemd install-etc
REMOVE_TARGETS := remove-bin remove-systemd remove-etc

ifdef MANDIR
INSTALL_TARGETS += install-man
REMOVE_TARGETS += remove-man
endif

ifdef EXAMPLESDIR
INSTALL_TARGETS += install-examples
REMOVE_TARGETS += remove-examples
endif

install: all $(INSTALL_TARGETS)

install-bin: $(EXECUTABLE)
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 $(EXECUTABLE) $(DESTDIR)$(BINDIR)

install-systemd:
	$(INSTALL) -d $(DESTDIR)$(SYSTEMDDIR)
	$(INSTALL) -m 644 ../contrib/systemd.service $(DESTDIR)$(SYSTEMDDIR)/$(EXECUTABLE).service

install-etc:
	$(INSTALL) -d $(DESTDIR)$(ETCDIR)/init.d/
	$(INSTALL) -m 755 ../contrib/initscript $(DESTDIR)$(ETCDIR)/init.d/$(EXECUTABLE)
	$(INSTALL) -d $(DESTDIR)$(ETCDIR)/default/
	$(INSTALL) -m 644 ../contrib/default $(DESTDIR)$(ETCDIR)/default/$(EXECUTABLE)
	@ echo "# $(EXECUTABLE) configuration file" > $(DESTDIR)$(ETCDIR)/$(EXECUTABLE).conf
	@ echo "# example configurations can be found at $(EXAMPLESDIR)/$(EXECUTABLE)" >> $(DESTDIR)$(ETCDIR)/$(EXECUTABLE).conf

install-examples:
	$(INSTALL) -d $(DESTDIR)$(EXAMPLESDIR)/$(EXECUTABLE)
	$(INSTALL) -m 644 ../contrib/example.conf $(DESTDIR)$(EXAMPLESDIR)/$(EXECUTABLE)/

install-man: manpage
	$(INSTALL) -d $(DESTDIR)$(MANDIR)/man8/
	$(INSTALL) -m 644 ../doc/tcpproxy.8 $(DESTDIR)$(MANDIR)/man8/$(EXECUTABLE).8

uninstall: remove

remove: $(REMOVE_TARGETS)

remove-bin:
	rm -f $(DESTDIR)$(BINDIR)/$(EXECUTABLE)

remove-systemd:
	rm -f $(DESTDIR)$(SYSTEMDDIR)/$(EXECUTABLE).service

remove-etc:
	rm -f $(DESTDIR)$(ETCDIR)/init.d/$(EXECUTABLE)

remove-examples:
	rm -rf $(DESTDIR)$(EXAMPLESDIR)/$(EXECUTABLE)/

remove-man:
	rm -f $(DESTDIR)$(MANDIR)/man8/$(EXECUTABLE).8

purge: remove
	rm -f $(DESTDIR)$(ETCDIR)/$(EXECUTABLE).conf
	rm -f $(DESTDIR)$(ETCDIR)/default/$(EXECUTABLE)
