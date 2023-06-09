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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

#include "datatypes.h"
#include "options.h"
#include "string_list.h"
#include "sig_handler.h"
#include "log.h"
#include "daemon.h"

#include "listener.h"
#include "clients.h"
#include "cfg_parser.h"

int main_loop(options_t* opt, listeners_t* listeners)
{
  log_printf(INFO, "entering main loop");

  int sig_fd = signal_init();
  if(sig_fd < 0)
    return -1;

  clients_t clients;
  int return_value = clients_init(&clients, opt->buffer_size_);

  while(!return_value) {
    fd_set readfds, writefds;
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_SET(sig_fd, &readfds);
    int nfds = sig_fd;
    listeners_read_fds(listeners, &readfds, &nfds);
    clients_read_fds(&clients, &readfds, &nfds);
    clients_write_fds(&clients, &writefds, &nfds);
    int ret = select(nfds + 1, &readfds, &writefds, NULL, NULL);
    if(ret == -1 && errno != EINTR) {
      log_printf(ERROR, "select returned with error: %s", strerror(errno));
      return_value = -1;
      break;
    }
    if(!ret || ret == -1)
      continue;

    if(FD_ISSET(sig_fd, &readfds)) {
      return_value = signal_handle();
      if(return_value == SIGINT || return_value == SIGQUIT || return_value == SIGTERM) break;
      if(return_value == SIGHUP) {
        if(opt->config_file_) {
          log_printf(NOTICE, "re-reading config file: %s", opt->config_file_);
          read_configfile(opt->config_file_, listeners);
        } else
          log_printf(NOTICE, "ignoring SIGHUP: no config file specified");

        return_value = 0;
      } else if(return_value == SIGUSR1) {
        listeners_print(listeners);
      } else if(return_value == SIGUSR2) {
        clients_print(&clients);
      }
    }

    return_value = listeners_handle_accept(listeners, &clients, &readfds);
    if(return_value) break;

    return_value = clients_write(&clients, &writefds);
    if(return_value) break;

    return_value = clients_read(&clients, &readfds);
  }

  clients_clear(&clients);
  signal_stop();
  return return_value;
}

int main(int argc, char* argv[])
{
  log_init();

  options_t opt;
  int ret = options_parse(&opt, argc, argv);
  if(ret) {
    if(ret > 0) {
      fprintf(stderr, "syntax error near: %s\n\n", argv[ret]);
    }
    if(ret == -2) {
      fprintf(stderr, "memory error on options_parse, exitting\n");
    }
    if(ret == -3) {
      options_print_version();
    }

    if(ret != -2 && ret != -3)
      options_print_usage();

    if(ret == -1 || ret == -3)
      ret = 0;

    options_clear(&opt);
    log_close();
    exit(ret);
  }
  slist_element_t* tmp = opt.log_targets_.first_;
  while(tmp) {
    ret = log_add_target(tmp->data_);
    if(ret) {
      switch(ret) {
      case -2: fprintf(stderr, "memory error on log_add_target, exitting\n"); break;
      case -3: fprintf(stderr, "unknown log target: '%s', exitting\n", (char*)(tmp->data_)); break;
      case -4: fprintf(stderr, "this log target is only allowed once: '%s', exitting\n", (char*)(tmp->data_)); break;
      default: fprintf(stderr, "syntax error near: '%s', exitting\n", (char*)(tmp->data_)); break;
      }

      options_clear(&opt);
      log_close();
      exit(ret);
    }
    tmp = tmp->next_;
  }

  log_printf(NOTICE, "just started...");
  options_parse_post(&opt);

  listeners_t listeners;
  ret = listeners_init(&listeners);
  if(ret) {
    options_clear(&opt);
    log_close();
    exit(-1);
  }

  if(opt.local_port_) {
    ret = listeners_add(&listeners, opt.local_addr_, opt.lresolv_type_, opt.local_port_, opt.remote_addr_, opt.rresolv_type_, opt.remote_port_, opt.source_addr_);
    if(!ret) ret = listeners_update(&listeners);
    if(ret) {
      listeners_clear(&listeners);
      options_clear(&opt);
      log_close();
      exit(-1);
    }
  } else {
    ret = read_configfile(opt.config_file_, &listeners);
    if(ret || !slist_length(&listeners)) {
      if(!ret)
        log_printf(ERROR, "no listeners defined in config file %s", opt.config_file_);
      listeners_clear(&listeners);
      options_clear(&opt);
      log_close();
      exit(-1);
    }
  }

  priv_info_t priv;
  if(opt.username_)
    if(priv_init(&priv, opt.username_, opt.groupname_)) {
      listeners_clear(&listeners);
      options_clear(&opt);
      log_close();
      exit(-1);
    }

  FILE* pid_file = NULL;
  if(opt.pid_file_) {
    pid_file = fopen(opt.pid_file_, "w");
    if(!pid_file) {
      log_printf(WARNING, "unable to open pid file: %s", strerror(errno));
    }
  }

  if(opt.chroot_dir_)
    if(do_chroot(opt.chroot_dir_)) {
      listeners_clear(&listeners);
      options_clear(&opt);
      log_close();
      exit(-1);
    }
  if(opt.username_)
    if(priv_drop(&priv)) {
      listeners_clear(&listeners);
      options_clear(&opt);
      log_close();
      exit(-1);
    }

  if(opt.daemonize_) {
    pid_t oldpid = getpid();
    daemonize();
    log_printf(INFO, "running in background now (old pid: %d)", oldpid);
  }

  if(pid_file) {
    pid_t pid = getpid();
    fprintf(pid_file, "%d", pid);
    fclose(pid_file);
  }

  ret = main_loop(&opt, &listeners);

  listeners_clear(&listeners);
  options_clear(&opt);

  if(!ret)
    log_printf(NOTICE, "normal shutdown");
  else if(ret < 0)
    log_printf(NOTICE, "shutdown after error");
  else {
    log_printf(NOTICE, "shutdown after signal");
    log_close();
    kill(getpid(), ret);
  }

  log_close();

  return ret;
}
