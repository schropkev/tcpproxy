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

#include "datatypes.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>

#include "listener.h"
#include "tcp.h"
#include "log.h"

#include "clients.h"

void listeners_delete_element(void* e)
{
  if(!e)
    return;

  listener_t* element = (listener_t*)e;
  if(element->fd_ >= 0)
    close(element->fd_);

  free(e);
}

int listeners_init(listeners_t* list)
{
  return slist_init(list, &listeners_delete_element);
}

void listeners_clear(listeners_t* list)
{
  slist_clear(list);
}

int listeners_add(listeners_t* list, const char* laddr, resolv_type_t lrt, const char* lport, const char* raddr, resolv_type_t rrt, const char* rport, const char* saddr)
{
  if(!list)
    return -1;

  if(!lport) { log_printf(ERROR, "no local port specified"); return -1; }
  if(!raddr) { log_printf(ERROR, "no remote address specified"); return -1; }
  if(!rport) { log_printf(ERROR, "no remote port specified"); return -1; }

// TODO: what if more than one address is returned here?
  struct addrinfo* re = tcp_resolve_endpoint(raddr, rport, rrt, 0);
  if(!re)
    return -1;

  struct addrinfo* se = NULL;
  if(saddr) {
    se = tcp_resolve_endpoint(saddr, NULL, rrt, 0);
    if(!se) {
      freeaddrinfo(re);
      return -1;
    }
  }

  struct addrinfo* le = tcp_resolve_endpoint(laddr, lport, lrt, 1);
  if(!le) {
    freeaddrinfo(re);
    if(se)
      freeaddrinfo(se);
    return -1;
  }

  struct addrinfo* l = le;
  int ret = 0;
  while(l) {
    listener_t* element = malloc(sizeof(listener_t));
    if(!element) {
      ret = -2;
      break;
    }
    memset(&(element->remote_end_.addr_), 0, sizeof(element->remote_end_.addr_));
    memcpy(&(element->remote_end_.addr_), re->ai_addr, re->ai_addrlen);
    element->remote_end_.len_ = re->ai_addrlen;

    memset(&(element->source_end_.addr_), 0, sizeof(element->source_end_.addr_));
    if(se) {
      memcpy(&(element->source_end_.addr_), se->ai_addr, se->ai_addrlen);
      element->source_end_.len_ = se->ai_addrlen;
    }
    else element->source_end_.addr_.ss_family = AF_UNSPEC;

    memset(&(element->local_end_.addr_), 0, sizeof(element->local_end_.addr_));
    memcpy(&(element->local_end_.addr_), l->ai_addr, l->ai_addrlen);
    element->local_end_.len_ = l->ai_addrlen;
    element->state_ = NEW;
    element->fd_ = -1;

    if(slist_add(list, element) == NULL) {
      free(element);
      ret = -2;
      break;
    }

    l = l->ai_next;
  }
  freeaddrinfo(re);
  if(se) freeaddrinfo(se);
  freeaddrinfo(le);

  return ret;
}

static int activate_listener(listener_t* l)
{
  if(!l || l->state_ != NEW)
    return -1;

  l->fd_ = socket(l->local_end_.addr_.ss_family, SOCK_STREAM, 0);
  if(l->fd_ < 0) {
    log_printf(ERROR, "Error on opening tcp socket: %s", strerror(errno));
    l->state_ = ZOMBIE;
    return -1;
  }

  int on = 1;
  int ret = setsockopt(l->fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  if(ret) {
    log_printf(ERROR, "Error on setsockopt(): %s", strerror(errno));
    l->state_ = ZOMBIE;
    return -1;
  }
  if(l->local_end_.addr_.ss_family == AF_INET6) {
    if(setsockopt(l->fd_, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)))
      log_printf(WARNING, "failed to set IPV6_V6ONLY socket option: %s", strerror(errno));
  }

  char* ls = tcp_endpoint_to_string(l->local_end_);
  ret = bind(l->fd_, (struct sockaddr *)&(l->local_end_.addr_), l->local_end_.len_);
  if(ret) {
    log_printf(ERROR, "Error on bind(%s): %s", ls ? ls:"", strerror(errno));
    if(ls) free(ls);
    l->state_ = ZOMBIE;
    return -1;
  }

  ret = listen(l->fd_, 0);
  if(ret) {
    log_printf(ERROR, "Error on listen(): %s", strerror(errno));
    if(ls) free(ls);
    l->state_ = ZOMBIE;
    return -1;
  }

  l->state_ = ACTIVE;

  char* rs = tcp_endpoint_to_string(l->remote_end_);
  char* ss = tcp_endpoint_to_string(l->source_end_);
  log_printf(NOTICE, "listening on: %s (remote: %s%s%s)", ls ? ls:"(null)", rs ? rs:"(null)", ss ? " with source " : "", ss ? ss : "");
  if(ls) free(ls);
  if(rs) free(rs);
  if(ss) free(ss);

  return 0;
}

static void update_listener(listener_t* dest, listener_t* src)
{
  if(!dest || !src || src->state_ != ZOMBIE || dest->state_ != NEW)
    return;

  dest->fd_ = src->fd_;
  src->fd_ = -1;
  dest->state_ = ACTIVE;

  char* ls = tcp_endpoint_to_string(dest->local_end_);
  char* rs = tcp_endpoint_to_string(dest->remote_end_);
  char* ss = tcp_endpoint_to_string(dest->source_end_);
  log_printf(NOTICE, "reusing %s with remote: %s%s%s", ls ? ls:"(null)", rs ? rs:"(null)", ss ? " and source " : "", ss ? ss : "");
  if(ls) free(ls);
  if(rs) free(rs);
  if(ss) free(ss);
}

static listener_t* find_zombie_listener(listeners_t* list, tcp_endpoint_t* local_end)
{
  if(!list)
    return NULL;

  slist_element_t* tmp = list->first_;
  while(tmp) {
    listener_t* l = (listener_t*)tmp->data_;
    if(l && l->state_ == ZOMBIE && l->local_end_.len_ == local_end->len_ &&
       !memcmp(&(l->local_end_.addr_), &(local_end->addr_), local_end->len_))
      return l;
    tmp = tmp->next_;
  }

  return NULL;
}

int listeners_update(listeners_t* list)
{
  if(!list)
    return 0;

  slist_element_t* tmp = list->first_;
  while(tmp) {
    listener_t* l = (listener_t*)tmp->data_;
    if(l && l->state_ == ACTIVE)
      l->state_ = ZOMBIE;
    tmp = tmp->next_;
  }

  int retval = 0;
  tmp = list->first_;
  while(tmp) {
    listener_t* l = (listener_t*)tmp->data_;
    int ret = 0;
    if(l && l->state_ == NEW) {
      listener_t* tmp = find_zombie_listener(list, &(l->local_end_));
      if(tmp)
        update_listener(l, tmp);
      else
        ret = activate_listener(l);
    }
    if(!retval) retval = ret;
    tmp = tmp->next_;
  }

  int cnt = 0;
  tmp = list->first_;
  while(tmp) {
    listener_t* l = (listener_t*)tmp->data_;
    tmp = tmp->next_;
    if(l && l->state_ == ZOMBIE) {
      cnt++;
      slist_remove(list, l);
    }
  }
  log_printf(DEBUG, "%d listener zombies removed", cnt);

  return retval;
}

void listeners_revert(listeners_t* list)
{
  if(!list)
    return;

  int cnt = 0;
  slist_element_t* tmp = list->first_;
  while(tmp) {
    listener_t* l = (listener_t*)tmp->data_;
    tmp = tmp->next_;
    if(l && l->state_ == NEW) {
      cnt++;
      slist_remove(list, l);
    }
  }

  log_printf(DEBUG, "%d new listeners reverted", cnt);
}

void listeners_remove(listeners_t* list, int fd)
{
  slist_remove(list, listeners_find(list, fd));
}

listener_t* listeners_find(listeners_t* list, int fd)
{
  if(!list)
    return NULL;

  slist_element_t* tmp = list->first_;
  while(tmp) {
    listener_t* l = (listener_t*)tmp->data_;
    if(l && l->fd_ == fd)
      return l;
    tmp = tmp->next_;
  }

  return NULL;
}

void listeners_print(listeners_t* list)
{
  if(!list)
    return;

  slist_element_t* tmp = list->first_;
  while(tmp) {
    listener_t* l = (listener_t*)tmp->data_;
    if(l) {
      char* ls = tcp_endpoint_to_string(l->local_end_);
      char* rs = tcp_endpoint_to_string(l->remote_end_);
      char* ss = tcp_endpoint_to_string(l->source_end_);
      char state = '?';
      switch(l->state_) {
      case NEW: state = 'n'; break;
      case ACTIVE: state = 'a'; break;
      case ZOMBIE: state = 'z'; break;
      }
      log_printf(NOTICE, "[%c] listener #%d: %s -> %s%s%s", state, l->fd_, ls ? ls : "(null)", rs ? rs : "(null)", ss ? " with source " : "", ss ? ss : "");
      if(ls) free(ls);
      if(rs) free(rs);
      if(ss) free(ss);
    }
    tmp = tmp->next_;
  }
}

void listeners_read_fds(listeners_t* list, fd_set* set, int* max_fd)
{
  if(!list)
    return;

  slist_element_t* tmp = list->first_;
  while(tmp) {
    listener_t* l = (listener_t*)tmp->data_;
    if(l && l->state_ == ACTIVE) {
      FD_SET(l->fd_, set);
      *max_fd = *max_fd > l->fd_ ? *max_fd : l->fd_;
    }
    tmp = tmp->next_;
  }
}

int listeners_handle_accept(listeners_t* list, clients_t* clients, fd_set* set)
{
  if(!list)
    return -1;

  slist_element_t* tmp = list->first_;
  while(tmp) {
    listener_t* l = (listener_t*)tmp->data_;
    if(l && FD_ISSET(l->fd_, set)) {
      tcp_endpoint_t remote_addr;
      remote_addr.len_ = sizeof(remote_addr.addr_);
      int new_client = accept(l->fd_, (struct sockaddr *)&(remote_addr.addr_), &remote_addr.len_);
      if(new_client == -1) {
        log_printf(ERROR, "Error on accept(): %s", strerror(errno));
        return -1;
      }
      char* rs = tcp_endpoint_to_string(remote_addr);
      log_printf(INFO, "new client from %s (fd=%d)", rs ? rs:"(null)", new_client);
      if(rs) free(rs);
      FD_CLR(l->fd_, set);

      clients_add(clients, new_client, l->remote_end_, l->source_end_);
    }
    tmp = tmp->next_;
  }

  return 0;
}
