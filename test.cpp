#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "httpserver.h"

void req_callback(http_client_t* client, char* http_req) {
    fprintf(stdout, "Received: %s\n", http_req);
    
    char* response = "HTTP/1.1 200 OK\r\n";
    http_write(client, response, strlen(response));
}

int main() {
    http_ctx_t http_ctx = {0};
    http_ctx.addr.ip = "127.0.0.1";
    http_ctx.addr.port = 80;
    
    //http_ctx.ssl.cert_path = "./cert.pem";
    //http_ctx.ssl.key_path = "./key.pem";

    http_ctx.callback = req_callback;

    assert(http_initialize(&http_ctx) == HTTP_RET_OK);
    http_listen();
    http_deinitialize();

    return 0;
}