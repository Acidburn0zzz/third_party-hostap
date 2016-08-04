// Copyright 2016 The Fuchsia Authors. All rights reserved.
// This software may be distributed under the terms of the BSD license.
// See README for more details.

extern "C" {
// Hostap code requires this be the first file included
#include "includes.h"

#include "eloop.h"
} // extern "C"

extern "C" int eloop_init() { return 0; }

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
  // TODO(alangardner): Implement
  return -1;
}

extern "C" int eloop_cancel_timeout(eloop_timeout_handler handler,
                                    void *eloop_data, void *user_data) {
  // TODO(alangardner): Implement
  return -1;
}

extern "C" int eloop_cancel_timeout_one(eloop_timeout_handler handler,
                                        void *eloop_data, void *user_data,
                                        struct os_reltime *remaining) {
  // TODO(alangardner): Implement
  return -1;
}

extern "C" int eloop_is_timeout_registered(eloop_timeout_handler handler,
                                           void *eloop_data, void *user_data) {
  // TODO(alangardner): Implement
  return -1;
}

extern "C" int eloop_deplete_timeout(unsigned int req_secs,
                                     unsigned int req_usecs,
                                     eloop_timeout_handler handler,
                                     void *eloop_data, void *user_data) {
  // TODO(alangardner): Implement
  return -1;
}

extern "C" int eloop_replenish_timeout(unsigned int req_secs,
                                       unsigned int req_usecs,
                                       eloop_timeout_handler handler,
                                       void *eloop_data, void *user_data) {
  // TODO(alangardner): Implement
  return -1;
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
  // TODO(alangardner): Implement
}

extern "C" void eloop_terminate() {
  // TODO(alangardner): Implement
}

extern "C" void eloop_destroy() {
  // TODO(alangardner): Implement
}

extern "C" int eloop_terminated() {
  // TODO(alangardner): Implement
  return 1;
}

extern "C" void eloop_wait_for_read_sock(int sock) {
  // Not implemented.
}
