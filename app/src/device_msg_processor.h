#ifndef SC_DEVICE_MSG_PROCESSOR_H
#define SC_DEVICE_MSG_PROCESSOR_H

#include "common.h"

#include <stdbool.h>
#include <json-c/json.h>

struct sc_device_msg_processor {
    int device_fd;
    char *msg_buffer;
    size_t buffer_size;
    struct json_object *config;
    struct json_object *current_msg;
    bool needs_cleanup;
};

bool
sc_device_msg_processor_init(struct sc_device_msg_processor *processor, int device_fd);

bool
sc_device_msg_processor_handle_message(struct sc_device_msg_processor *processor);

void
sc_device_msg_processor_destroy(struct sc_device_msg_processor *processor);

#endif