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

#ifndef TCPPROXY_options_h_INCLUDED
#define TCPPROXY_options_h_INCLUDED

#include "string_list.h"
#include "datatypes.h"
#include "tcp.h"

struct options_struct {
  char* progname_;
  int daemonize_;
  char* username_;
  char* groupname_;
  char* chroot_dir_;
  char* pid_file_;
  string_list_t log_targets_;
  char* local_addr_;
  resolv_type_t lresolv_type_;
  char* local_port_;
  char* remote_addr_;
  resolv_type_t rresolv_type_;
  char* remote_port_;
  char* source_addr_;
  char* config_file_;
  int32_t buffer_size_;
  int debug_;
};
typedef struct options_struct options_t;

int options_parse_hex_string(const char* hex, buffer_t* buffer);

int options_parse(options_t* opt, int argc, char* argv[]);
void options_parse_post(options_t* opt);
void options_default(options_t* opt);
void options_clear(options_t* opt);
void options_print_usage();
void options_print_version();
void options_print(options_t* opt);

#endif
