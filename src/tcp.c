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

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "datatypes.h"

#include "tcp.h"
#include "log.h"

char* tcp_endpoint_to_string(tcp_endpoint_t e)
{
  char addrstr[INET6_ADDRSTRLEN + 1], portstr[6], *ret;
  char addrport_sep = ':';

  switch(e.addr_.ss_family)
  {
  case AF_INET: addrport_sep = ':'; break;
  case AF_INET6: addrport_sep = '.'; break;
  case AF_UNSPEC: return NULL;
  default: return strdup("unknown address type");
  }

  int errcode  = getnameinfo((struct sockaddr *)&(e.addr_), e.len_, addrstr, sizeof(addrstr), portstr, sizeof(portstr), NI_NUMERICHOST | NI_NUMERICSERV);
  if (errcode != 0) return NULL;
  int len = asprintf(&ret, "%s%c%s", addrstr, addrport_sep, portstr);
  if(len == -1) return NULL;
  return ret;
}

struct addrinfo* tcp_resolve_endpoint(const char* addr, const char* port, resolv_type_t rt, int passive)
{
  struct addrinfo hints, *res;

  res = NULL;
  memset (&hints, 0, sizeof (hints));
  hints.ai_socktype = SOCK_STREAM;
  if(passive)
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;

  switch(rt) {
  case IPV4_ONLY: hints.ai_family = AF_INET; break;
  case IPV6_ONLY: hints.ai_family = AF_INET6; break;
  default: hints.ai_family = AF_UNSPEC; break;
  }

  int errcode = getaddrinfo(addr, port, &hints, &res);
  if (errcode != 0) {
    char* type = "";
    if(rt == IPV4_ONLY) type = "IPv4 ";
    else if(rt == IPV6_ONLY) type = "IPv6 ";
    log_printf(ERROR, "Error resolving %saddress (%s:%s): %s", type, (addr) ? addr : "*", (port) ? port : "0", gai_strerror(errcode));
    return NULL;
  }
  if(!res) {
    log_printf(ERROR, "getaddrinfo returned no address for %s:%s", (addr) ? addr : "*", (port) ? port : "0");
    return NULL;
  }

  return res;
}
