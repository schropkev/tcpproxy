/*
 *  tcpproxy
 *
 *  tcpproxy is a simple tcp connection proxy which combines the
 *  features of rinetd and 6tunnel. tcpproxy supports IPv4 and
 *  IPv6 and also supports connections from IPv6 to IPv4
 *  endpoints and vice versa.
 *
 *
 *  Copyright (C) 2010-2015 Christian Pointner <equinox@spreadspace.org>
 *
 *  This file is part of tcpproxy.
 *
 *  tcpproxy is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  any later version.
 *
 *  tcpproxy is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with tcpproxy. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef TCPPROXY_tcp_h_INCLUDED
#define TCPPROXY_tcp_h_INCLUDED

#include <sys/types.h>
#include <sys/socket.h>

enum resolv_type_enum { ANY, IPV4_ONLY, IPV6_ONLY };
typedef enum resolv_type_enum resolv_type_t;

typedef struct {
  socklen_t len_;
  struct sockaddr_storage addr_;
} tcp_endpoint_t;

char* tcp_endpoint_to_string(tcp_endpoint_t e);
struct addrinfo* tcp_resolve_endpoint(const char* addr, const char* port, resolv_type_t rt, int passive);

#endif
