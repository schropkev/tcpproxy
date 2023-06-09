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

#ifndef TCPPROXY_slist_h_INCLUDED
#define TCPPROXY_slist_h_INCLUDED

struct slist_element_struct {
  void* data_;
  struct slist_element_struct* next_;
};
typedef struct slist_element_struct slist_element_t;

slist_element_t* slist_get_last(slist_element_t* first);

struct slist_struct {
  void (*delete_element)(void* element);
  slist_element_t* first_;
};
typedef struct slist_struct slist_t;

int slist_init(slist_t* lst, void (*delete_element)(void*));
slist_element_t* slist_add(slist_t* lst, void* data);
void slist_remove(slist_t* lst, void* data);
void slist_clear(slist_t* lst);
int slist_length(slist_t* lst);

#endif
