/*
 * A mock driver used for exercising wpa_supplicant code.
 *
 * Copyright (c) 2016 The Fuchsia Authors
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 */

#include "includes.h"

#include <stdbool.h>

#include "common.h"
#include "driver.h"
#include "eloop.h"
#include "os.h"

static const u8 MOCK_BSSID[ETH_ALEN] = {0, 1, 2, 3, 4, 5};
static const u8 MOCK_SSID[6] = {'M', 'o', 'c', 'k', 'A', 'p'};

// TODO(alangardner): queue wpa_supplicant_event calls on eloop
struct mock_driver_data {
  void *ctx;
  struct wpa_driver_capa capa;
  struct wpa_scan_results *scan_results;
  bool associated;
};

static int mock_driver_send_ether(void *priv, const u8 *dst, const u8 *src,
                                  u16 proto, const u8 *data, size_t data_len) {
  return 0;
}

static void mock_driver_enabled(void *eloop_data, void *user_ctx) {
  struct mock_driver_data *drv = eloop_data;
  wpa_supplicant_event(drv->ctx, EVENT_INTERFACE_DISABLED, NULL);
  wpa_supplicant_event(drv->ctx, EVENT_INTERFACE_ENABLED, NULL);
}

static void mock_driver_scan_completed(void *eloop_data, void *user_ctx) {
  struct mock_driver_data *drv = eloop_data;
  wpa_supplicant_event(drv->ctx, EVENT_SCAN_RESULTS, NULL);
}

static void mock_driver_disassociated(void *eloop_data, void *user_ctx) {
  struct mock_driver_data *drv = eloop_data;
  drv->associated = false;
  wpa_supplicant_event(drv->ctx, EVENT_DISASSOC, NULL);
}

static void mock_driver_associated(void *eloop_data, void *user_ctx) {
  struct mock_driver_data *drv = eloop_data;
  drv->associated = true;
  wpa_supplicant_event(drv->ctx, EVENT_ASSOC, NULL);
  eloop_register_timeout(5, 0, mock_driver_disassociated, drv, NULL);
}

static void mock_driver_capa(struct mock_driver_data *drv) {
  drv->capa.key_mgmt =
      WPA_DRIVER_CAPA_KEY_MGMT_WPA | WPA_DRIVER_CAPA_KEY_MGMT_WPA_PSK |
      WPA_DRIVER_CAPA_KEY_MGMT_WPA2 | WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK;
  drv->capa.enc = WPA_DRIVER_CAPA_ENC_WEP40 | WPA_DRIVER_CAPA_ENC_WEP104 |
                  WPA_DRIVER_CAPA_ENC_TKIP | WPA_DRIVER_CAPA_ENC_CCMP;
  drv->capa.flags |= WPA_DRIVER_FLAGS_AP;
  drv->capa.max_scan_ssids = 1;
  drv->capa.auth =
      WPA_DRIVER_AUTH_OPEN | WPA_DRIVER_AUTH_SHARED | WPA_DRIVER_AUTH_LEAP;
}

static void mock_scan_results(struct mock_driver_data *drv) {
  int ssid_len = sizeof(MOCK_SSID) / sizeof(*MOCK_SSID);
  int bssid_len = sizeof(MOCK_BSSID) / sizeof(*MOCK_BSSID);
  int ie_len = 2 + ssid_len;
  struct wpa_scan_res *result = os_zalloc(sizeof(struct wpa_scan_res));
  result->flags = 0;
  os_memcpy(&result->bssid, MOCK_BSSID, bssid_len);
  result->freq = 2412;  // Channel 1
  result->beacon_int = 100;
  result->caps = 0;
  result->qual = 0;
  result->noise = 0;
  result->level = 0;
  // Note: 'tsf' and 'age' will get updated when scan is called
  result->est_throughput = 0;
  result->snr = 0;
  result->ie_len = ie_len;
  result->beacon_ie_len = 0;

  u8 *pos = (u8 *)(result + 1);
  *pos++ = WLAN_EID_SSID;
  *pos++ = ssid_len;
  os_memcpy(pos, MOCK_SSID, ssid_len);
  pos += ssid_len;

  drv->scan_results = os_zalloc(sizeof(struct wpa_scan_results));
  drv->scan_results->num = 1;
  drv->scan_results->res = os_calloc(1, sizeof(struct wpa_scan_res *));
  drv->scan_results->res[0] = result;
}

static void *mock_driver_init(void *ctx, const char *ifname) {
  wpa_printf(MSG_DEBUG, "MOCK INIT");
  struct mock_driver_data *drv = os_zalloc(sizeof(struct mock_driver_data));
  if (drv == NULL) {
    wpa_printf(MSG_ERROR, "Could not allocate memory for mock driver data");
    return NULL;
  }
  drv->ctx = ctx;
  mock_driver_capa(drv);
  mock_scan_results(drv);
  drv->associated = false;

  eloop_register_timeout(0, 0, mock_driver_enabled, drv, NULL);
  return drv;
}

static void mock_driver_deinit(void *priv) {
  struct mock_driver_data *drv = priv;
  wpa_scan_results_free(drv->scan_results);
  os_free(drv);
}

static int mock_driver_get_capa(void *priv, struct wpa_driver_capa *capa) {
  wpa_printf(MSG_DEBUG, "MOCK GET CAPA");
  struct mock_driver_data *drv = priv;
  os_memcpy(capa, &drv->capa, sizeof(*capa));
  return 0;
}

static int mock_driver_scan(void *priv, struct wpa_driver_scan_params *params) {
  wpa_printf(MSG_DEBUG, "MOCK SCAN");
  struct mock_driver_data *drv = priv;
  eloop_register_timeout(0, 0, mock_driver_scan_completed, drv, NULL);
  return 0;
}

static struct wpa_scan_results *mock_driver_get_scan_results(void *priv) {
  wpa_printf(MSG_DEBUG, "MOCK GET SCAN RESULTS");
  struct mock_driver_data *drv = priv;
  return drv->scan_results;
}

static int mock_driver_associate(void *priv,
                                 struct wpa_driver_associate_params *params) {
  struct mock_driver_data *drv = priv;
  eloop_register_timeout(0, 0, mock_driver_associated, drv, NULL);
  return 0;
}

static int mock_driver_get_bssid(void *priv, u8 *bssid) {
  struct mock_driver_data *drv = priv;
  if (drv->associated) {
    os_memcpy(bssid, &MOCK_BSSID, ETH_ALEN);
  } else {
    os_memset(bssid, 0, ETH_ALEN);
  }
  return 0;
}

static int mock_driver_get_ssid(void *priv, u8 *ssid) {
  struct mock_driver_data *drv = priv;
  if (drv->associated) {
    os_memcpy(ssid, &MOCK_SSID, sizeof(MOCK_SSID));
    return sizeof(MOCK_SSID);
  } else {
    return 0;
  }
}

const struct wpa_driver_ops wpa_driver_mock_ops = {
    .name = "mock",
    .desc = "simulates a working driver for testing",
    .send_ether = mock_driver_send_ether,
    .init = mock_driver_init,
    .deinit = mock_driver_deinit,
    .get_capa = mock_driver_get_capa,
    .scan2 = mock_driver_scan,
    .get_scan_results2 = mock_driver_get_scan_results,
    .associate = mock_driver_associate,
    .get_bssid = mock_driver_get_bssid,
    .get_ssid = mock_driver_get_ssid,
};
