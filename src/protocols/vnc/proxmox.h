/*
 * Proxmox helper for VNC proxying
 */
#ifndef GUAC_VNC_PROXMOX_H
#define GUAC_VNC_PROXMOX_H

#include "config.h"
#include <guacamole/client.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Attempts to retrieve a Proxmox VNC ticket and set the VNC password within
 * the connection settings to that ticket value.
 *
 * This currently supports Proxmox API token authentication via
 * `proxmox_token_name`/`proxmox_token_value`. If token auth is not
 * configured, the function will log an error and fail.
 *
 * @param client
 *     The guac_client whose settings contain the proxmox connection info.
 *
 * @return
 *     Zero on success (settings->password has been set), non-zero on
 *     failure.
 */
int guac_vnc_proxmox_start_proxy(guac_client* client);

#ifdef __cplusplus
}
#endif

#endif
