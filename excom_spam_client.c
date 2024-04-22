#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "excom_protocol.h"

#define ASSERT(cond, fmt, ...) \
    if (!(cond)) { \
        fprintf(stderr, "ASSERT(%s): %s:%d: ", #cond, __FILE__, __LINE__); \
        fprintf(stderr, fmt, __VA_ARGS__); \
        exit(1); \
    }


int main()
{
    // Use STDIN/STDOUT in binary mode
    int out_fd = fileno(stdout);
    int in_fd = fileno(stdin);

    // Use static buffers
    static uint8_t req_buf[1024];
    static uint8_t resp_buf[1024];
    request_t *req = (request_t *) req_buf;
    response_t *resp = (response_t *) resp_buf;

    uint32_t req_id = 0;
    int ec = 0;

    size_t req_count = 0;
    static uint8_t tx_buf[4 * 1024];
    size_t tx_len = 0;

    for (size_t i = 0; i < 42; ++i) {
        // Construct request
        *req = (request_t) {
            .id = ++req_id,
            .type = REQ_DISPLAY,
        };
        size_t req_size = REQUEST_BASE_SIZE + sizeof(req->data.display);
        int n = snprintf(req->data.display.text, sizeof(req_buf) - req_size, "Hello world %zu!", i);
        ASSERT(n > 0, "n=%d\n", n);

        req->data.display.text_length = n;
        req_size += n;

        ASSERT(sizeof(tx_buf) - tx_len >= req_size, "tx_len=%zu", tx_len);
        memcpy(&tx_buf[tx_len], req, req_size);
        tx_len += req_size;
        req_count++;
    }

    size_t sent = 0;
    size_t chunk_len = 33;
    while (sent < tx_len) {
        size_t remaining = tx_len - sent;
        size_t len = remaining > chunk_len ? chunk_len : remaining;

        // Send chunk to server
        ec = write(out_fd, &tx_buf[sent], len);
        ASSERT(ec >= 0, "ec=%d\n", ec);
        sent += len;

        // Try to force TCP chunking
        fflush(stdout);
        usleep(5 * 1000);
    }

    for (size_t i = 0; i < req_count; ++i) {
        // Read response
        ec = read(in_fd, resp, sizeof(*resp));
        ASSERT(ec == sizeof(*resp), "ec=%d\n", ec);
        ASSERT(resp->id == i + 1, "resp->id=%d\n", resp->id);
    }

    close(out_fd);

    return 0;
}
