#include <stdio.h>
#include <stdlib.h>
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

    bool ok = false;
    for (size_t i = 0; !ok; ++i) {
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

        // Send it to server
        ec = write(out_fd, req, req_size);
        ASSERT(ec >= 0, "ec=%d\n", ec);

        // Read response
        ec = read(in_fd, resp, sizeof(*resp));
        ASSERT(ec == sizeof(*resp), "ec=%d\n", ec);
        ASSERT(resp->id == req_id, "resp->id=%d\n", resp->id);
        ok = resp->status;
    }

    for (size_t i = 0; i < 42; ++i) {
        // Send request
        *req = (request_t) {
            .id = ++req_id,
            .type = REQ_LED,
            .data.led = {
                .id = i,
                .state = i % 2 == 0,
            },
        };
        ec = write(out_fd, req, REQUEST_BASE_SIZE + sizeof(req->data.led));
        ASSERT(ec >= 0, "ec=%d\n", ec);

        // Read response
        ec = read(in_fd, resp, sizeof(*resp));
        ASSERT(ec == sizeof(*resp), "ec=%d\n", ec);
        ASSERT(resp->id == req_id, "resp->id=%d\n", resp->id);
    }

    close(out_fd);

    return 0;
}
