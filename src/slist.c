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

#include <unistd.h>
#include <stdlib.h>

#include "datatypes.h"

#include "slist.h"

slist_element_t* slist_get_last(slist_element_t* first)
{
  if(!first)
    return NULL;

  while(first->next_)
    first = first->next_;

  return first;
}

int slist_init(slist_t* lst, void (*delete_element)(void*))
{
  if(!lst || !delete_element)
    return -1;

  lst->delete_element = delete_element;
  lst->first_ = NULL;

  return 0;
}

slist_element_t* slist_add(slist_t* lst, void* data)
{
  if(!lst || !data)
    return NULL;

  slist_element_t* new_element = malloc(sizeof(slist_element_t));
  if(!new_element)
    return NULL;

  new_element->data_ = data;
  new_element->next_ = NULL;

  if(!lst->first_)
    lst->first_ = new_element;
  else
    slist_get_last(lst->first_)->next_ = new_element;

  return new_element;
}

void slist_remove(slist_t* lst, void* data)
{
  if(!lst || !lst->first_ || !data)
    return;

  slist_element_t* tmp = lst->first_->next_;
  slist_element_t* prev = lst->first_;
  if(lst->first_->data_ == data) {
    lst->first_ = tmp;
    lst->delete_element(prev->data_);
    free(prev);
  }
  else {
    while(tmp) {
      if(tmp->data_ == data) {
        prev->next_ = tmp->next_;
        lst->delete_element(tmp->data_);
        free(tmp);
        return;
      }
      prev = tmp;
      tmp = tmp->next_;
    }
  }
}

void slist_clear(slist_t* lst)
{
  if(!lst || !lst->first_)
    return;

  do {
    slist_element_t* deletee = lst->first_;
    lst->first_ = lst->first_->next_;
    lst->delete_element(deletee->data_);
    free(deletee);
  }
  while(lst->first_);

  lst->first_ = NULL;
}

int slist_length(slist_t* lst)
{
  if(!lst || !lst->first_)
    return 0;

  int len = 0;
  slist_element_t* tmp;
  for(tmp = lst->first_; tmp; tmp = tmp->next_)
    len++;

  return len;
}
