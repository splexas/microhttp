#ifdef __cplusplus
extern "C" {
#endif

#include "httpserver.h"

#include <stdio.h>
#include <pthread.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#ifdef HTTP_SSL_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>
SSL_CTX* ssl_ctx;
#endif

int http_server_state = 1;
int server_fd;
http_ctx_t* _http_ctx;

int http_initialize(http_ctx_t* http_ctx) {
    _http_ctx = http_ctx;

    #ifdef HTTP_SSL_TLS
    const SSL_METHOD* method = TLS_server_method();
    ssl_ctx = SSL_CTX_new(method);
    if (ssl_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return HTTP_RET_ERR;
    }

    if (SSL_CTX_use_certificate_file(ssl_ctx, http_ctx->ssl.cert_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return HTTP_RET_ERR;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, http_ctx->ssl.key_path, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return HTTP_RET_ERR;
    }
    #endif

    #ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2,2), &wsa_data) != 0) {
        fprintf(stderr, "Failed to WSAStartup.\n");
        http_deinitialize();
        return HTTP_RET_ERR;
    }
    #endif

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        fprintf(stderr, "Failed to create server socket.\n");
        http_deinitialize();
        return HTTP_RET_ERR;
    }

    struct sockaddr_in addr_in = {0};
    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons(http_ctx->addr.port);
    
    if (inet_pton(AF_INET, http_ctx->addr.ip, &(addr_in.sin_addr)) != 1) {
        fprintf(stderr, "Failed to turn the ip address to network byte order using inet_pton.");
        http_deinitialize();
        return HTTP_RET_ERR;
    }

    struct sockaddr addr = *(struct sockaddr*)&addr_in;
    if (bind(server_fd, &addr, sizeof(addr)) != 0) {
        fprintf(stderr, "Failed to bind the address to server socket.");
        http_deinitialize();
        return HTTP_RET_ERR;
    }

    if (listen(server_fd, 255) != 0) {
        fprintf(stderr, "Failed to listen for connections.");
        http_deinitialize();
        return HTTP_RET_ERR;
    }

    return HTTP_RET_OK;
}

void http_listen() {
    while (http_server_state == 1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd == -1)
            continue;

        http_client_t http_client = {0};
        http_client.socket = client_fd;

        #ifdef HTTP_SSL_TLS
        /* Wrap the socket around ssl and perform the ssl/tls handshake */
        SSL* ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            http_close(&http_client);
            continue;
        }

        http_client.ssl = (void*)ssl;
        #endif

        pthread_t thread_id;
        pthread_create(&thread_id, NULL, http_handle, (void*)&http_client); 
        pthread_detach(thread_id);
    }
}

void* http_handle(void* _http_client) {
    http_client_t http_client = *(http_client_t*)_http_client;

    char buf[4096];
    if (http_read(&http_client, buf, sizeof(buf)) == HTTP_RET_OK)
        _http_ctx->callback(&http_client, buf);

    http_close(&http_client);    
    return NULL;
}

int http_write(http_client_t* client, char* data, int data_len) {
    #ifdef HTTP_SSL_TLS
    if (SSL_write(client->ssl, data, data_len) <= 0)
        return HTTP_RET_ERR;
    #else
    if (send(client->socket, data, data_len, 0) <= 0)
        return HTTP_RET_ERR;
    #endif

    return HTTP_RET_OK;
}

int http_read(http_client_t* client, char* data, int data_len) {
    #ifdef HTTP_SSL_TLS
    if (SSL_read(client->ssl, data, data_len) <= 0)
        return HTTP_RET_ERR;
    #else
    if (recv(client->socket, data, data_len, 0) <= 0)
        return HTTP_RET_ERR;
    #endif

    return HTTP_RET_OK;
}

void http_close(http_client_t* client) {
    #ifdef HTTP_SSL_TLS
    if (client->ssl != NULL) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
    }
    #endif

    #ifdef _WIN32
    closesocket(client->socket);
    #else
    close(client->socket);
    #endif
}

void http_deinitialize() {
    if (server_fd != -1) {
        #ifdef _WIN32
        closesocket(server_fd);
        #else
        close(server_fd);
        #endif
    }

    #ifdef HTTP_SSL_TLS
    SSL_CTX_free(ssl_ctx);
    #endif

    #ifdef _WIN32
    WSACleanup();
    #endif
}

#ifdef __cplusplus
}
#endif
