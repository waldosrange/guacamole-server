/*
 * Proxmox VNC helper implementation using OpenSSL for HTTPS requests.
 */

#include "config.h"
#include "proxmox.h"
#include "settings.h"
#include "vnc.h"

#include <guacamole/client.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Extract hostname and port from a given host string. If no port is specified,
 * default_port is used. The caller must free *out_host. */
static int parse_host_port(const char* input, char** out_host, char** out_port, const char* default_port) {
    if (!input) return -1;

    const char* start = input;
    /* Skip scheme if present */
    const char* p = strstr(input, "://");
    if (p) start = p + 3;

    /* Copy until '/' or end */
    const char* end = strchr(start, '/');
    size_t len = end ? (size_t)(end - start) : strlen(start);

    char* hostport = (char*) malloc(len + 1);
    if (!hostport) return -1;
    memcpy(hostport, start, len);
    hostport[len] = '\0';

    /* Look for ':' indicating a port */
    char* colon = strchr(hostport, ':');
    if (colon) {
        *colon = '\0';
        *out_host = strdup(hostport);
        *out_port = strdup(colon + 1);
        free(hostport);
        return 0;
    }

    *out_host = strdup(hostport);
    *out_port = strdup(default_port);
    free(hostport);
    return 0;
}

/* Read all data from SSL connection into a dynamically allocated buffer. */
static char* ssl_read_all(guac_client* client, SSL* ssl) {
    size_t cap = 4196;
    size_t len = 0;
    char* buf = malloc(cap);
    if (!buf) return NULL;

    while (1) {
        int r = SSL_read(ssl, buf + len, (int)(cap - len - 1));

        if (r > 0) {
            len += r;
            /* Expand buffer if we're getting close to capacity */
            if (len >= cap - 1024) {
                cap *= 2;
                char* tmp = realloc(buf, cap);
                if (!tmp) { free(buf); return NULL; }
                buf = tmp;
            }
        } else {
            int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_ZERO_RETURN) {
                /* Connection closed cleanly by peer - this is normal EOF */
                break;
            } else {
                /* Other error - log and break */
                guac_client_log(client, GUAC_LOG_WARN, "SSL_read error: %d", err);
                break;
            }
        }
    }

    /* Null-terminate */
    buf[len] = '\0';
    return buf;
}

/* Parse a JSON string value for a given key in the response body.
 * Returns a malloc'd string on success, or NULL on failure.
 * The caller must free the returned string.
 * Handles escaped characters in JSON strings. */
static char* parse_json_string(const char* body, const char* key) {
    if (!body || !key) return NULL;

    char* found = strstr(body, key);
    if (!found) return NULL;

    char* colon = strchr(found, ':');
    if (!colon) return NULL;

    /* Find the opening quote */
    char* start = strchr(colon, '"');
    if (!start) return NULL;
    start++;

    /* Find the closing quote, handling escaped characters */
    char* end = start;
    while (*end) {
        if (*end == '\\') {
            /* Skip escaped character */
            end++;
            if (!*end) return NULL;
            end++;
        } else if (*end == '"') {
            /* Found unescaped closing quote */
            break;
        } else {
            end++;
        }
    }

    if (*end != '"') return NULL;

    size_t len = (size_t)(end - start);
    char* result = (char*) malloc(len + 1);
    if (!result) return NULL;

    memcpy(result, start, len);
    result[len] = '\0';
    return result;
}

int guac_vnc_proxmox_start_proxy(guac_client* client) {

    guac_vnc_client* vnc_client = (guac_vnc_client*) client->data;
    guac_vnc_settings* settings = vnc_client->settings;

    if (!settings || !settings->proxmox_host || !settings->proxmox_node || !settings->proxmox_vm_id) {
        guac_client_log(client, GUAC_LOG_ERROR, "Proxmox VNC proxy configuration incomplete.");
        return 1;
    }

    if (!settings->proxmox_token_name || !settings->proxmox_token_value || !settings->proxmox_user) {
        guac_client_log(client, GUAC_LOG_ERROR,
                "Proxmox VNC proxy requires token-based authentication (proxmox_token_name/proxmox_token_value/proxmox_user).");
        return 1;
    }

    SSL_library_init();
    SSL_load_error_strings();
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        guac_client_log(client, GUAC_LOG_ERROR, "Failed to create SSL context.");
        return 1;
    }


    /* Parse host and port */
    char* host = NULL;
    char* port = NULL;
    if (parse_host_port(settings->proxmox_host, &host, &port, "8006") != 0) {
        guac_client_log(client, GUAC_LOG_ERROR, "Failed to parse proxmox host.");
        SSL_CTX_free(ctx);
        return 1;
    }

    /* Resolve address */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int rv = getaddrinfo(host, port, &hints, &res);
    if (rv != 0) {
        guac_client_log(client, GUAC_LOG_ERROR, "DNS lookup failed for %s: %s", host, gai_strerror(rv));
        free(host); free(port); SSL_CTX_free(ctx);
        return 1;
    }

    int sock = -1;
    struct addrinfo* ai;
    for (ai = res; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    if (sock < 0) {
        guac_client_log(client, GUAC_LOG_ERROR, "Failed to connect to %s:%s", host, port);
        free(host); free(port); SSL_CTX_free(ctx);
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        guac_client_log(client, GUAC_LOG_ERROR, "Failed to create SSL object.");
        close(sock); free(host); free(port); SSL_CTX_free(ctx);
        return 1;
    }
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) != 1) {
        guac_client_log(client, GUAC_LOG_ERROR, "SSL handshake failed for %s:%s", host, port);
        SSL_free(ssl); close(sock); free(host); free(port); SSL_CTX_free(ctx);
        return 1;
    }


    /* Build request path */
    char path[512];
    snprintf(path, sizeof(path), "/api2/json/nodes/%s/qemu/%s/vncproxy",
            settings->proxmox_node, settings->proxmox_vm_id);

    /* Build Authorization header */
    char auth_hdr[1024];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: PVEAPIToken=%s!%s=%s",
            settings->proxmox_user,
            settings->proxmox_token_name,
            settings->proxmox_token_value);

    /* Build HTTP POST request */
    char req[2048];
    snprintf(req, sizeof(req),
            "POST %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "%s\r\n"
            "Connection: close\r\n"
            "Content-Length: 0\r\n"
            "\r\n",
            path, host, auth_hdr);

    /* Send request */
    int to_write = (int) strlen(req);
    int written = 0;
    while (written < to_write) {
        int w = SSL_write(ssl, req + written, to_write - written);
        if (w <= 0) break;
        written += w;
    }

    /* Read response */
    char* resp = ssl_read_all(client, ssl);
    if (!resp) {
        guac_client_log(client, GUAC_LOG_ERROR, "Failed to read response from Proxmox API.");
        SSL_shutdown(ssl); SSL_free(ssl); close(sock); free(host); free(port); SSL_CTX_free(ctx);
        return 1;
    }

    /* Extract response body */
    char* body = strstr(resp, "\r\n\r\n");
    if (body) body += 4; else body = resp;

    /* Parse ticket from response */
    char* ticket = parse_json_string(body, "\"ticket\"", client);
    if (!ticket) {
        guac_client_log(client, GUAC_LOG_ERROR, "Proxmox API response did not contain ticket.");
        free(resp); SSL_shutdown(ssl); SSL_free(ssl); close(sock); free(host); free(port); SSL_CTX_free(ctx);
        return 1;
    }

    /* Parse port from response */
    char* port_str = parse_json_string(body, "\"port\"", client);
    if (!port_str) {
        guac_client_log(client, GUAC_LOG_ERROR, "Proxmox API response did not contain port.");
        free(resp); SSL_shutdown(ssl); SSL_free(ssl); close(sock); free(host); free(port); SSL_CTX_free(ctx);
        return 1;
    }
    if (settings->password) free(settings->password);
    settings->password = strdup(ticket);

    /* Set port from response */
    settings->port = atoi(port_str);
    free(port_str);
    guac_client_log(client, GUAC_LOG_INFO, "Retrieved Proxmox ticket and port from API.");

    free(ticket);
    free(resp);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    free(host); free(port);
    SSL_CTX_free(ctx);

    return 0;
}
