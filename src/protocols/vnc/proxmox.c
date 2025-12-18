/*
 * Proxmox VNC helper implementation using OpenSSL for HTTPS requests.
 */

#include "config.h"
#include "proxmox.h"
#include "settings.h"
#include "vnc.h"

#include <guacamole/client.h>
#include <guacamole/log.h>

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

/* Helper: determine whether a host string starts with an HTTP scheme */
static int has_scheme(const char* host) {
    if (!host) return 0;
    return (strncasecmp(host, "http://", 7) == 0 || strncasecmp(host, "https://", 8) == 0);
}

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
static char* ssl_read_all(SSL* ssl) {
    size_t cap = 4096;
    size_t len = 0;
    char* buf = malloc(cap);
    if (!buf) return NULL;

    for (;;) {
        int r = SSL_read(ssl, buf + len, (int)(cap - len));
        if (r > 0) {
            len += r;
            if (len + 1 >= cap) {
                cap *= 2;
                char* tmp = realloc(buf, cap);
                if (!tmp) { free(buf); return NULL; }
                buf = tmp;
            }
            continue;
        }
        int err = SSL_get_error(ssl, r);
        if (r <= 0) break;
    }

    /* Null-terminate */
    buf[len] = '\0';
    return buf;
}

int guac_vnc_proxmox_set_password(guac_client* client) {

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

    /* Require verification of the server certificate and load system
     * default CA locations. If the default paths cannot be loaded, fail. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        guac_client_log(client, GUAC_LOG_ERROR, "Failed to load system CA certificates for TLS verification.");
        SSL_CTX_free(ctx);
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

    /* Verify the certificate chain result */
    long verify_res = SSL_get_verify_result(ssl);
    if (verify_res != X509_V_OK) {
        guac_client_log(client, GUAC_LOG_ERROR, "TLS certificate verification failed for %s: %s",
                host, X509_verify_cert_error_string(verify_res));
        SSL_shutdown(ssl); SSL_free(ssl); close(sock); free(host); free(port); SSL_CTX_free(ctx);
        return 1;
    }

    /* Hostname/IP verification against the certificate. Accept either DNS
     * names (via X509_check_host) or literal IP addresses listed in the
     * certificate's subjectAltName (GEN_IPADD). */
    {
        X509* cert = SSL_get_peer_certificate(ssl);
        if (!cert) {
            guac_client_log(client, GUAC_LOG_ERROR, "No TLS certificate presented by %s", host);
            SSL_shutdown(ssl); SSL_free(ssl); close(sock); free(host); free(port); SSL_CTX_free(ctx);
            return 1;
        }

        int matched = 0;

        /* If host is an IP literal, check IP SAN entries. */
        unsigned char ipbuf[16];
        if (inet_pton(AF_INET, host, ipbuf) == 1) {
            GENERAL_NAMES* san = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
            if (san) {
                int san_count = sk_GENERAL_NAME_num(san);
                for (int i = 0; i < san_count && !matched; i++) {
                    GENERAL_NAME* gn = sk_GENERAL_NAME_value(san, i);
                    if (gn->type == GEN_IPADD) {
                        ASN1_OCTET_STRING* ip = gn->d.iPAddress;
                        if (ip && ip->length == 4 && memcmp(ip->data, ipbuf, 4) == 0) {
                            matched = 1;
                        }
                    }
                }
                GENERAL_NAMES_free(san);
            }
        }
        else if (inet_pton(AF_INET6, host, ipbuf) == 1) {
            GENERAL_NAMES* san = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
            if (san) {
                int san_count = sk_GENERAL_NAME_num(san);
                for (int i = 0; i < san_count && !matched; i++) {
                    GENERAL_NAME* gn = sk_GENERAL_NAME_value(san, i);
                    if (gn->type == GEN_IPADD) {
                        ASN1_OCTET_STRING* ip = gn->d.iPAddress;
                        if (ip && ip->length == 16 && memcmp(ip->data, ipbuf, 16) == 0) {
                            matched = 1;
                        }
                    }
                }
                GENERAL_NAMES_free(san);
            }
        }
        else {
            /* Not an IP literal: use X509_check_host for DNS names */
            if (X509_check_host(cert, host, 0, 0, NULL) == 1)
                matched = 1;
        }

        X509_free(cert);

        if (!matched) {
            guac_client_log(client, GUAC_LOG_ERROR, "TLS hostname/IP verification failed for %s", host);
            SSL_shutdown(ssl); SSL_free(ssl); close(sock); free(host); free(port); SSL_CTX_free(ctx);
            return 1;
        }
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

    /* Build HTTP GET request */
    char req[2048];
    snprintf(req, sizeof(req),
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "%s\r\n"
            "Connection: close\r\n"
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
    char* resp = ssl_read_all(ssl);
    if (!resp) {
        guac_client_log(client, GUAC_LOG_ERROR, "Failed to read response from Proxmox API.");
        SSL_shutdown(ssl); SSL_free(ssl); close(sock); free(host); free(port); SSL_CTX_free(ctx);
        return 1;
    }

    /* Look for "vncticket":"..." in response body */
    char* body = strstr(resp, "\r\n\r\n");
    if (body) body += 4; else body = resp;

    char* key = "\"vncticket\"";
    char* found = strstr(body, key);
    if (!found) {
        guac_client_log(client, GUAC_LOG_ERROR, "Proxmox API response did not contain vncticket.");
        free(resp); SSL_shutdown(ssl); SSL_free(ssl); close(sock); free(host); free(port); SSL_CTX_free(ctx);
        return 1;
    }

    char* colon = strchr(found, ':');
    if (!colon) {
        guac_client_log(client, GUAC_LOG_ERROR, "Malformed Proxmox API response (vncticket).");
        free(resp); SSL_shutdown(ssl); SSL_free(ssl); close(sock); free(host); free(port); SSL_CTX_free(ctx);
        return 1;
    }

    char* start = strchr(colon, '"');
    if (!start) {
        guac_client_log(client, GUAC_LOG_ERROR, "Malformed Proxmox API vncticket value.");
        free(resp); SSL_shutdown(ssl); SSL_free(ssl); close(sock); free(host); free(port); SSL_CTX_free(ctx);
        return 1;
    }
    start++;
    char* end = strchr(start, '"');
    if (!end) {
        guac_client_log(client, GUAC_LOG_ERROR, "Malformed Proxmox API vncticket value (unterminated string).");
        free(resp); SSL_shutdown(ssl); SSL_free(ssl); close(sock); free(host); free(port); SSL_CTX_free(ctx);
        return 1;
    }

    size_t ticket_len = (size_t)(end - start);
    char* ticket = (char*) malloc(ticket_len + 1);
    if (!ticket) {
        free(resp); SSL_shutdown(ssl); SSL_free(ssl); close(sock); free(host); free(port); SSL_CTX_free(ctx);
        return 1;
    }
    memcpy(ticket, start, ticket_len);
    ticket[ticket_len] = '\0';

    if (settings->password) free(settings->password);
    settings->password = strdup(ticket);

    guac_client_log(client, GUAC_LOG_INFO, "Retrieved Proxmox vncticket and set VNC password.");

    free(ticket);
    free(resp);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    free(host); free(port);
    SSL_CTX_free(ctx);

    return 0;
}
