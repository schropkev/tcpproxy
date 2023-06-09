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

VERSION=$(shell cat ../version)

.PHONY: clean

all: manpage

tcpproxy.8: tcpproxy.8.txt
	a2x -f manpage $<
	@ sed -i -e 's/\[FIXME: source\]/tcpproxy ${VERSION}/' $@
	@ sed -i -e 's/\[FIXME: manual\]/tcpproxy user manual/' $@
	@ sed -i -e 's/^tcpproxy$$/\\fBtcpproxy\\fR/' $@
	@ sed -i -e 's/^  \[ \([^ ]*\)/  [ \\fB\1\\fR/' $@

manpage: tcpproxy.8

clean:
	rm -f tcpproxy.8.xml

realclean: clean
	rm -f tcpproxy.8
