// excom proto - EXample COMmunication Protocol
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define __packed __attribute__((__packed__))

enum RequestType {
    REQ_DISPLAY = 1,
    REQ_LED = 2,
};

typedef struct  {
    uint32_t text_length;
    char text[];
} __packed display_request_t;

typedef struct {
    uint16_t id;
    bool state;
} __packed led_request_t;

typedef union {
    display_request_t display;
    led_request_t led;
} __packed request_data_t;

typedef struct {
    uint32_t id;
    uint8_t type;
    request_data_t data;
} __packed request_t;

typedef struct {
    uint32_t id;
    bool status;
} __packed response_t;

#define REQUEST_BASE_SIZE (sizeof(request_t) - sizeof(request_data_t))
