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

#ifndef TCPPROXY_log_h_INCLUDED
#define TCPPROXY_log_h_INCLUDED

#define MSG_LENGTH_MAX 1024

enum log_prio_enum { ERROR = 1, WARNING = 2, NOTICE = 3,
                     INFO = 4, DEBUG = 5 };
typedef enum log_prio_enum log_prio_t;

const char* log_prio_to_string(log_prio_t prio);

enum log_target_type_enum { TARGET_SYSLOG , TARGET_STDOUT, TARGET_STDERR, TARGET_FILE , TARGET_UNKNOWN };
typedef enum log_target_type_enum log_target_type_t;

struct log_target_struct {
  log_target_type_t type_;
  int (*init)(struct log_target_struct* self, const char* conf);
  void (*open)(struct log_target_struct* self);
  void (*log)(struct log_target_struct* self, log_prio_t prio, const char* msg);
  void (*close)(struct log_target_struct* self);
  void (*clear)(struct log_target_struct* self);
  int opened_;
  int enabled_;
  log_prio_t max_prio_;
  void* param_;
  struct log_target_struct* next_;
};
typedef struct log_target_struct log_target_t;


struct log_targets_struct {
  log_target_t* first_;
};
typedef struct log_targets_struct log_targets_t;

int log_targets_target_exists(log_targets_t* targets, log_target_type_t type);
int log_targets_add(log_targets_t* targets, const char* conf);
void log_targets_log(log_targets_t* targets, log_prio_t prio, const char* msg);
void log_targets_clear(log_targets_t* targets);


struct log_struct {
  log_prio_t max_prio_;
  log_targets_t targets_;
};
typedef struct log_struct log_t;

void log_init();
void log_close();
void update_max_prio();
int log_add_target(const char* conf);
void log_printf(log_prio_t prio, const char* fmt, ...);
void log_print_hex_dump(log_prio_t prio, const uint8_t* buf, uint32_t len);

#endif
