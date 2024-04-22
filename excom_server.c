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

void respond(int fd, uint32_t id, bool status)
{
    static uint8_t resp_buf[1024];
    response_t *resp = (response_t *) resp_buf;
    *resp = (response_t) {
        .id = id,
        .status = status,
    };
    int ec = write(fd, resp_buf, sizeof(*resp));
    ASSERT(ec >= 0, "ec=%d\n", ec);
}

int main()
{
    // Use STDIN/STDOUT in binary mode
    int out_fd = fileno(stdout);
    int in_fd = fileno(stdin);

    static uint8_t req_buf[1024];
    request_t *req = (request_t *) req_buf;

    const size_t ok_every = 42;
    size_t ok_after = ok_every;

    while (true) {
        uint8_t *buf = req_buf;
        int ec = read(in_fd, buf, REQUEST_BASE_SIZE);
        if (ec == 0) { // EOF
            break;
        }
        buf += ec;


        switch (req->type) {
            case REQ_DISPLAY: {
                ec = read(in_fd, buf, sizeof(req->data.display.text_length));
                ASSERT(ec == sizeof(req->data.display.text_length), "ec=%d\n", ec);
                buf += ec;

                ec = read(in_fd, buf, req->data.display.text_length);
                ASSERT(ec == req->data.display.text_length, "ec=%d\n", ec);

                respond(out_fd, req->id, ok_after == 0);
                ok_after = ok_after == 0 ? ok_every : ok_after - 1;

                break;
            }
            case REQ_LED: {
                ec = read(in_fd, buf, sizeof(req->data.led));
                ASSERT(ec == sizeof(req->data.led), "ec=%d\n", ec);

                respond(out_fd, req->id, ok_after == 0);
                ok_after = ok_after == 0 ? ok_every : ok_after - 1;

                break;
            }
            default: ASSERT(false, "req->type=%d\n", req->type); break;
        }
    }

    close(out_fd);

    return 0;
}

