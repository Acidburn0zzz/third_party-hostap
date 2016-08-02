// Copyright 2016 The Fuchsia Authors. All rights reserved.
// This software may be distributed under the terms of the BSD license.
// See README for more details.

extern "C" {
// Hostap code requires this be the first file included
#include "includes.h"

#include "eloop.h"
}  // extern "C"

#include <assert.h>
#include <stdint.h>

#include <algorithm>
#include <list>
#include <memory>

#include "lib/ftl/time/time_delta.h"
#include "lib/ftl/time/time_point.h"
#include "lib/mtl/tasks/message_loop.h"

extern "C" {
#include "os.h"
}  // extern "C"

constexpr int64_t kUsecPerSec = 1000000L;

struct EloopTimeout {
  int id;
  eloop_timeout_handler handler;
  void *eloop_data;
  void *user_data;
  ftl::TimeDelta delay;
  ftl::TimePoint approx_end_time;
};

static mtl::MessageLoop *loop;
static std::list<EloopTimeout> *timeouts;
static int current_registration_id = 0;

static std::list<EloopTimeout>::iterator find_timeout(
    eloop_timeout_handler handler, void *eloop_data, void *user_data) {
  return std::find_if(timeouts->begin(), timeouts->end(),
                      [handler, eloop_data, user_data](EloopTimeout timeout) {
                        return timeout.handler == handler &&
                               timeout.eloop_data == eloop_data &&
                               timeout.user_data == user_data;
                      });
}

static ftl::TimeDelta time_delta(unsigned int secs, unsigned int usecs) {
  return ftl::TimeDelta::FromSeconds(secs) +
         ftl::TimeDelta::FromMicroseconds(usecs);
}

static ftl::TimeDelta remaining_time_delta(ftl::TimePoint end_time) {
  ftl::TimePoint now = ftl::TimePoint::Now();
  return end_time > now ? ftl::TimeDelta::Zero() : end_time - now;
}

extern "C" int eloop_init() {
  assert(loop == nullptr);
  loop = new mtl::MessageLoop();
  timeouts = new std::list<EloopTimeout>();
  return 0;
}

extern "C" int eloop_register_read_sock(int sock, eloop_sock_handler handler,
                                        void *eloop_data, void *user_data) {
  // Not implemented.
  return -1;
}

extern "C" void eloop_unregister_read_sock(int sock) {
  // Not implemented.
}

extern "C" int eloop_register_sock(int sock, eloop_event_type type,
                                   eloop_sock_handler handler, void *eloop_data,
                                   void *user_data) {
  // Not implemented.
  return -1;
}

extern "C" void eloop_unregister_sock(int sock, eloop_event_type type) {
  // Not implemented.
}

extern "C" int eloop_register_event(void *event, size_t event_size,
                                    eloop_event_handler handler,
                                    void *eloop_data, void *user_data) {
  // Not implemented.
  return -1;
}

extern "C" void eloop_unregister_event(void *event, size_t event_size) {
  // Not implemented.
}

extern "C" int eloop_register_timeout(unsigned int secs, unsigned int usecs,
                                      eloop_timeout_handler handler,
                                      void *eloop_data, void *user_data) {
  ftl::TimeDelta delay = time_delta(secs, usecs);
  int registration_id = ++current_registration_id;
  EloopTimeout timeout = {registration_id, handler,
                          eloop_data,      user_data,
                          delay,           ftl::TimePoint::Now() + delay};
  timeouts->push_back(timeout);
  loop->task_runner()->PostDelayedTask(
      [registration_id] {
        for (auto timeout = timeouts->begin(); timeout != timeouts->end();
             ++timeout) {
          if (registration_id == timeout->id) {
            timeout->handler(timeout->eloop_data, timeout->user_data);
            timeouts->erase(timeout);
            break;
          }
        }
      },
      delay);
  return 0;
}

extern "C" int eloop_cancel_timeout(eloop_timeout_handler handler,
                                    void *eloop_data, void *user_data) {
  int old_size = std::distance(timeouts->begin(), timeouts->end());
  timeouts->erase(
      std::remove_if(timeouts->begin(), timeouts->end(),
                     [handler, eloop_data, user_data](EloopTimeout timeout) {
                       return timeout.handler == handler &&
                              (timeout.eloop_data == eloop_data ||
                               eloop_data == ELOOP_ALL_CTX) &&
                              (timeout.user_data == user_data ||
                               user_data == ELOOP_ALL_CTX);
                     }),
      timeouts->end());
  int new_size = std::distance(timeouts->begin(), timeouts->end());
  return old_size - new_size;
}

extern "C" int eloop_cancel_timeout_one(eloop_timeout_handler handler,
                                        void *eloop_data, void *user_data,
                                        struct os_reltime *remaining) {
  std::list<EloopTimeout>::iterator timeout =
      find_timeout(handler, eloop_data, user_data);
  if (timeout == timeouts->end()) {
    return 0;
  } else {
    ftl::TimeDelta remaining_delta =
        remaining_time_delta(timeout->approx_end_time);
    remaining->sec = remaining_delta.ToSeconds();
    remaining->usec = remaining_delta.ToMicroseconds() % kUsecPerSec;
    timeouts->erase(timeout);
    return 1;
  }
}

extern "C" int eloop_is_timeout_registered(eloop_timeout_handler handler,
                                           void *eloop_data, void *user_data) {
  return find_timeout(handler, eloop_data, user_data) == timeouts->end() ? 0
                                                                         : 1;
}

extern "C" int eloop_deplete_timeout(unsigned int req_secs,
                                     unsigned int req_usecs,
                                     eloop_timeout_handler handler,
                                     void *eloop_data, void *user_data) {
  std::list<EloopTimeout>::iterator timeout =
      find_timeout(handler, eloop_data, user_data);
  if (timeout == timeouts->end()) {
    return -1;
  } else if (remaining_time_delta(timeout->approx_end_time) >
             time_delta(req_secs, req_usecs)) {
    timeouts->erase(timeout);
    // Note: Current implementation of register cannot fail.
    eloop_register_timeout(req_secs, req_usecs, handler, eloop_data, user_data);
    return 1;
  } else {
    return 0;
  }
}

extern "C" int eloop_replenish_timeout(unsigned int req_secs,
                                       unsigned int req_usecs,
                                       eloop_timeout_handler handler,
                                       void *eloop_data, void *user_data) {
  std::list<EloopTimeout>::iterator timeout =
      find_timeout(handler, eloop_data, user_data);
  if (timeout == timeouts->end()) {
    return -1;
  } else if (remaining_time_delta(timeout->approx_end_time) <
             time_delta(req_secs, req_usecs)) {
    timeouts->erase(timeout);
    // Note: Current implementation of register cannot fail.
    eloop_register_timeout(req_secs, req_usecs, handler, eloop_data, user_data);
    return 1;
  } else {
    return 0;
  }
}

extern "C" int eloop_register_signal(int sig, eloop_signal_handler handler,
                                     void *user_data) {
  // Not implemented.
  return -1;
}

extern "C" int eloop_register_signal_terminate(eloop_signal_handler handler,
                                               void *user_data) {
  // Not implemented.
  return -1;
}

extern "C" int eloop_register_signal_reconfig(eloop_signal_handler handler,
                                              void *user_data) {
  // Not implemented.
  return -1;
}

extern "C" void eloop_run() {
  assert(loop);
  loop->Run();
}

extern "C" void eloop_terminate() {
  assert(loop);
  loop->QuitNow();
}

extern "C" void eloop_destroy() {
  assert(loop);
  loop->QuitNow();
  delete loop;
  loop = nullptr;
  delete timeouts;
}

extern "C" int eloop_terminated() { return loop ? 0 : 1; }

extern "C" void eloop_wait_for_read_sock(int sock) {
  // Not implemented.
}
