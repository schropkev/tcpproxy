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

#ifndef TCPPROXY_listener_h_INCLUDED
#define TCPPROXY_listener_h_INCLUDED

#include <sys/select.h>

#include "slist.h"
#include "tcp.h"
#include "clients.h"

enum listener_state_enum { NEW, ACTIVE, ZOMBIE };
typedef enum listener_state_enum listener_state_t;

typedef struct {
  int fd_;
  tcp_endpoint_t local_end_;
  tcp_endpoint_t remote_end_;
  tcp_endpoint_t source_end_;
  listener_state_t state_;
} listener_t;

void listeners_delete_element(void* e);

typedef slist_t listeners_t;

int listeners_init(listeners_t* list);
void listeners_clear(listeners_t* list);
int listeners_add(listeners_t* list, const char* laddr, resolv_type_t lrt, const char* lport, const char* raddr, resolv_type_t rrt, const char* rport, const char* saddr);
int listeners_update(listeners_t* list);
void listeners_revert(listeners_t* list);
void listeners_remove(listeners_t* list, int fd);
listener_t* listeners_find(listeners_t* list, int fd);
void listeners_print(listeners_t* list);

void listeners_read_fds(listeners_t* list, fd_set* set, int* max_fd);
int listeners_handle_accept(listeners_t* list, clients_t* clients, fd_set* set);

#endif
