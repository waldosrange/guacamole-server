/*
 * Proxmox VNC helper implementation
 */

#include "config.h"
#include "proxmox.h"
#include "settings.h"
#include "vnc.h"

#include <guacamole/client.h>
#include <guacamole/log.h>

#include <curl/curl.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Simple write callback to capture HTTP response into a dynamically
 * allocated buffer. */
struct memory_chunk {
    char* data;
    size_t size;
};

static size_t write_cb(void* ptr, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct memory_chunk* mem = (struct memory_chunk*) userp;

    char* tmp = (char*) realloc(mem->data, mem->size + realsize + 1);
    if (!tmp)
        return 0; /* out of memory */

    mem->data = tmp;
    memcpy(&(mem->data[mem->size]), ptr, realsize);
    mem->size += realsize;
    mem->data[mem->size] = '\0';

    return realsize;
}

/* Helper: determine whether a host string starts with an HTTP scheme */
static int has_scheme(const char* host) {
    if (!host) return 0;
    return (strncasecmp(host, "http://", 7) == 0 || strncasecmp(host, "https://", 8) == 0);
}

int guac_vnc_proxmox_set_password(guac_client* client) {

    guac_vnc_client* vnc_client = (guac_vnc_client*) client->data;
    guac_vnc_settings* settings = vnc_client->settings;

    if (!settings || !settings->proxmox_host || !settings->proxmox_node || !settings->proxmox_vm_id) {
        guac_client_log(client, GUAC_LOG_ERROR, "Proxmox VNC proxy configuration incomplete.");
        return 1;
    }

    /* Require API token for this implementation */
    if (!settings->proxmox_token_name || !settings->proxmox_token_value || !settings->proxmox_user) {
        guac_client_log(client, GUAC_LOG_ERROR,
                "Proxmox VNC proxy requires token-based authentication (proxmox_token_name/proxmox_token_value/proxmox_user).\n");
        return 1;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        guac_client_log(client, GUAC_LOG_ERROR, "Unable to initialize HTTP client.");
        return 1;
    }

    /* Build base host URL */
    char base[1024];
    if (has_scheme(settings->proxmox_host)) {
        snprintf(base, sizeof(base), "%s", settings->proxmox_host);
    }
    else {
        snprintf(base, sizeof(base), "https://%s:8006", settings->proxmox_host);
    }

    /* Build vncproxy URL: /api2/json/nodes/{node}/qemu/{vmid}/vncproxy */
    char url[2048];
    snprintf(url, sizeof(url), "%s/api2/json/nodes/%s/qemu/%s/vncproxy",
            base, settings->proxmox_node, settings->proxmox_vm_id);

    struct memory_chunk chunk;
    chunk.data = (char*) malloc(1);
    chunk.size = 0;

    /* Authorization header using token */
    char auth_hdr[1024];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: PVEAPIToken=%s!%s=%s",
            settings->proxmox_user,
            settings->proxmox_token_name,
            settings->proxmox_token_value);

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, auth_hdr);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*) &chunk);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    /* Perform request */
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        guac_client_log(client, GUAC_LOG_ERROR, "Proxmox API request failed: %s", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(chunk.data);
        return 1;
    }

    /* Look for "vncticket":"..." in response */
    char* key = "\"vncticket\"";
    char* found = strstr(chunk.data, key);
    if (!found) {
        guac_client_log(client, GUAC_LOG_ERROR, "Proxmox API response did not contain vncticket.");
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(chunk.data);
        return 1;
    }

    /* Move to after the key, then to the opening quote of the value */
    char* colon = strchr(found, ':');
    if (!colon) {
        guac_client_log(client, GUAC_LOG_ERROR, "Malformed Proxmox API response (vncticket). ");
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(chunk.data);
        return 1;
    }

    /* Find the first '"' after colon */
    char* start = strchr(colon, '"');
    if (!start) {
        guac_client_log(client, GUAC_LOG_ERROR, "Malformed Proxmox API vncticket value.");
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(chunk.data);
        return 1;
    }
    start++; /* move past opening quote */

    char* end = strchr(start, '"');
    if (!end) {
        guac_client_log(client, GUAC_LOG_ERROR, "Malformed Proxmox API vncticket value (unterminated string).");
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(chunk.data);
        return 1;
    }

    size_t ticket_len = (size_t)(end - start);
    char* ticket = (char*) malloc(ticket_len + 1);
    memcpy(ticket, start, ticket_len);
    ticket[ticket_len] = '\0';

    /* Replace existing password if present */
    if (settings->password) free(settings->password);
    settings->password = strdup(ticket);

    guac_client_log(client, GUAC_LOG_INFO, "Retrieved Proxmox vncticket and set VNC password.");

    free(ticket);
    free(chunk.data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return 0;
}
