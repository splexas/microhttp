#ifndef HTTPSERVER_H
#define HTTPSERVER_H

#ifdef __cplusplus
extern "C" {
#endif

enum http_ret {
    HTTP_RET_OK,
    HTTP_RET_ERR
};

typedef struct {
    char* ip;
    int port;
} http_addr_t;

typedef struct {
    char* cert_path;
    char* key_path;
} http_ssl_t;

typedef struct {
    int socket;
    void* ssl;
} http_client_t;

typedef struct {
    http_addr_t addr;
    http_ssl_t ssl;
    void (*callback)(http_client_t* client, char* http_request);
} http_ctx_t;

/*
Used for stopping the server manually.
* 0 - the server doesn't function
* 1 - the server will function
*/
extern int http_server_state;

int http_initialize(http_ctx_t* http_ctx);

void http_listen();
void* http_handle(void* _http_client);

int http_write(http_client_t* client, char* data, int data_len);
int http_read(http_client_t* client, char* data, int data_len);

void http_close(http_client_t* client);

void http_deinitialize();

#ifdef __cplusplus
}
#endif

#endif