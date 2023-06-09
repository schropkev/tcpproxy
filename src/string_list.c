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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "string_list.h"
#include "slist.h"

int string_list_init(string_list_t* list)
{
  return slist_init(list, &free);
}

void string_list_clear(string_list_t* list)
{
  slist_clear(list);
}

int string_list_add(string_list_t* list, const char* string)
{
  if(!list)
    return -1;

  char* tmp = strdup(string);
  if(slist_add(list, tmp) == NULL) {
    free(tmp);
    return -2;
  }

  return 0;
}

void string_list_print(string_list_t* list, const char* head, const char* tail)
{
  if(!list)
    return;

  slist_element_t* tmp = list->first_;
  while(tmp) {
    printf("%s%s%s", head, (char*)(tmp->data_), tail);
    tmp = tmp->next_;
  }
}
