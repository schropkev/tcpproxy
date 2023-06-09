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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "datatypes.h"
#include "log.h"
#include "options.h"
#include "tcp.h"
#include "listener.h"

struct listener {
  char* la_;
  resolv_type_t lrt_;
  char* lp_;
  char* ra_;
  resolv_type_t rrt_;
  char* rp_;
  char* sa_;
};

static void init_listener_struct(struct listener* l)
{
  if(!l) return;

  l->la_ = NULL;
  l->lrt_ = ANY;
  l->lp_ = NULL;
  l->ra_ = NULL;
  l->rrt_ = ANY;
  l->rp_ = NULL;
  l->sa_ = NULL;
}

static void clear_listener_struct(struct listener* l)
{
  if(!l) return;

  if(l->la_)
    free(l->la_);
  if(l->lp_)
    free(l->lp_);
  if(l->ra_)
    free(l->ra_);
  if(l->rp_)
    free(l->rp_);
  if(l->sa_)
    free(l->sa_);

  init_listener_struct(l);
}

static int owrt_string(char** dest, char* start, char* end)
{
  if(!dest || start >= end)
    return -1;

  if(*dest) free(*dest);
  int n = end - start;
  *dest = malloc(n+1);
  if(!(*dest))
    return -2;

  memcpy(*dest, start, n);
  (*dest)[n] = 0;

  return 0;
}

%%{
  machine cfg_parser;

  action set_cpy_start  { cpy_start = fpc; }
  action set_local_addr { ret = owrt_string(&(lst.la_), cpy_start, fpc); cpy_start = NULL; }
  action set_local_port { ret = owrt_string(&(lst.lp_), cpy_start, fpc); cpy_start = NULL; }
  action set_local_resolv4 { lst.lrt_ = IPV4_ONLY; }
  action set_local_resolv6 { lst.lrt_ = IPV6_ONLY; }
  action set_remote_addr { ret = owrt_string(&(lst.ra_), cpy_start, fpc); cpy_start = NULL; }
  action set_remote_port { ret = owrt_string(&(lst.rp_), cpy_start, fpc); cpy_start = NULL; }
  action set_remote_resolv4 { lst.rrt_ = IPV4_ONLY; }
  action set_remote_resolv6 { lst.rrt_ = IPV6_ONLY; }
  action set_source_addr { ret = owrt_string(&(lst.sa_), cpy_start, fpc); cpy_start = NULL; }
  action add_listener {
    ret = listeners_add(listener, lst.la_, lst.lrt_, lst.lp_, lst.ra_, lst.rrt_, lst.rp_, lst.sa_);
    clear_listener_struct(&lst);
  }
  action logerror {
    if(fpc == eof)
      log_printf(ERROR, "config file syntax error: unexpected end of file");
    else
      log_printf(ERROR, "config file syntax error at line %d", cur_line);

    fgoto *cfg_parser_error;
  }

  newline = '\n' @{cur_line++;};
  ws = [ \t];
  comment = '#' [^\n]* newline;
  ign = ( ws | comment | newline | [\v\f\r] );

  number = [0-9]+;
  ipv4_addr = [0-9.]+;
  ipv6_addr = [0-9a-fA-F:]+;
  name = [a-zA-Z0-9\-]+;
  host_name = [a-zA-Z0-9\-.]+;
  tok_ipv4 = "ipv4"i;
  tok_ipv6 = "ipv6"i;

  host_or_addr = ( host_name | ipv4_addr | ipv6_addr );
  service = ( number | name );

  local_addr = ( '*' | host_or_addr >set_cpy_start %set_local_addr );
  local_port = service >set_cpy_start %set_local_port;
  lresolv = ( tok_ipv4 @set_local_resolv4 | tok_ipv6 @set_local_resolv6 );

  remote_addr = host_or_addr >set_cpy_start %set_remote_addr;
  remote_port = service >set_cpy_start %set_remote_port;
  rresolv = ( tok_ipv4 @set_remote_resolv4 | tok_ipv6 @set_remote_resolv6 );

  source_addr = host_or_addr >set_cpy_start %set_source_addr;

  resolv = "resolv" ws* ":" ws+ lresolv ws* ";";
  remote = "remote" ws* ":" ws+ remote_addr ws+ remote_port ws* ";";
  remote_resolv = "remote-resolv" ws* ":" ws+ rresolv ws* ";";
  source = "source" ws* ":" ws+ source_addr ws* ";";

  listen_head = 'listen' ws+ local_addr ws+ local_port;
  listen_body = '{' ( ign+ | resolv | remote | remote_resolv | source )* '};' @add_listener;

  main := ( listen_head ign* listen_body | ign+ )* $!logerror;
}%%


int parse_listener(char* p, char* pe, listeners_t* listener)
{
  int cs, ret = 0, cur_line = 1;

  %% write data;
  %% write init;

  char* cpy_start = NULL;
  struct listener lst;
  init_listener_struct(&lst);

  char* eof = pe;
  %% write exec;

  if(cs == cfg_parser_error) {
    listeners_revert(listener);
    ret = 1;
  }
  else
    ret = listeners_update(listener);

  clear_listener_struct(&lst);

  return ret;
}

int read_configfile(const char* filename, listeners_t* listener)
{
  int fd = open(filename, 0);
  if(fd < 0) {
    log_printf(ERROR, "open('%s') failed: %s", filename, strerror(errno));
    return -1;
  }

  struct stat sb;
  if(fstat(fd, &sb) == -1) {
    log_printf(ERROR, "fstat() error: %s", strerror(errno));
    close(fd);
    return -1;
  }

  if(!sb.st_size) {
    log_printf(ERROR, "config file %s is empty", filename);
    close(fd);
    return -1;
  }

  if(!S_ISREG(sb.st_mode)) {
    log_printf(ERROR, "config file %s is not a regular file", filename);
    close(fd);
    return -1;
  }

  char* p = (char*)mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if(p == MAP_FAILED) {
    log_printf(ERROR, "mmap() error: %s", strerror(errno));
    close(fd);
    return -1;
  }
  close(fd);

  log_printf(DEBUG, "mapped %ld bytes from file %s at address 0x%08lX", sb.st_size, filename, p);
  int ret = parse_listener(p, p + sb.st_size, listener);

  if(munmap(p, sb.st_size) == -1) {
    log_printf(ERROR, "munmap() error: %s", strerror(errno));
    return -1;
  }
  log_printf(DEBUG, "unmapped file %s", filename);

  return ret;
}
