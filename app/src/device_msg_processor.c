#include "device_msg_processor.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <json-c/json.h>

#include "log.h"

struct sc_device_msg_processor {
    int device_fd;
    char *msg_buffer;
    size_t buffer_size;
    struct json_object *config;
    struct json_object *current_msg;
    bool needs_cleanup;
};

static bool
parse_message(struct sc_device_msg_processor *processor, ssize_t len) {
    if (len < 2) {
        return false;
    }

    // Parse message type and content
    char msg_type = processor->msg_buffer[0];
    char *content = processor->msg_buffer + 1;
    size_t content_len = len - 1;

    // Create JSON object for the message
    processor->current_msg = json_object_new_object();
    if (!processor->current_msg) {
        LOG_OOM();
        return false;
    }

    // Add message type and content to JSON
    json_object_object_add(processor->current_msg, "type", 
                          json_object_new_int(msg_type));
    json_object_object_add(processor->current_msg, "content",
                          json_object_new_string_len(content, content_len));

    return true;
}

static bool
process_config_update(struct sc_device_msg_processor *processor) {
    struct json_object *config_obj;
    if (!json_object_object_get_ex(processor->current_msg, "content", &config_obj)) {
        return false;
    }

    const char *config_str = json_object_get_string(config_obj);
    if (!config_str) {
        return false;
    }

    // Parse new configuration
    struct json_object *new_config = json_tokener_parse(config_str);
    if (!new_config) {
        return false;
    }

    // Free old config and update
    if (processor->config) {
        json_object_put(processor->config);
    }
    processor->config = new_config;
    processor->needs_cleanup = true;
    return true;
}

static bool
handle_special_command(struct sc_device_msg_processor *processor) {
    struct json_object *content_obj;
    if (!json_object_object_get_ex(processor->current_msg, "content", &content_obj)) {
        return false;
    }

    const char *cmd = json_object_get_string(content_obj);
    if (!cmd || cmd[0] != 'X') {
        return false;
    }

    // Process special command
    LOGI("Processing special command: %s", cmd);
    
    // Free the message buffer as it's no longer needed
    free(processor->msg_buffer);
    processor->needs_cleanup = true;
    return true;
}

bool
sc_device_msg_processor_init(struct sc_device_msg_processor *processor, int device_fd) {
    processor->device_fd = device_fd;
    processor->buffer_size = 1024;
    processor->msg_buffer = malloc(processor->buffer_size);
    processor->config = NULL;
    processor->current_msg = NULL;
    processor->needs_cleanup = false;
    
    if (!processor->msg_buffer) {
        LOG_OOM();
        return false;
    }
    return true;
}

bool
sc_device_msg_processor_handle_message(struct sc_device_msg_processor *processor) {
    //SOURCE
    ssize_t r = read(processor->device_fd, processor->msg_buffer, processor->buffer_size);
    if (r <= 0) {
        return false;
    }

    // Parse the message into JSON
    if (!parse_message(processor, r)) {
        LOGW("Failed to parse message");
        return false;
    }

    // Handle different message types
    struct json_object *type_obj;
    if (json_object_object_get_ex(processor->current_msg, "type", &type_obj)) {
        int msg_type = json_object_get_int(type_obj);
        
        switch (msg_type) {
            case 'C': // Config update
                if (!process_config_update(processor)) {
                    LOGW("Failed to process config update");
                }
                break;
            case 'S': // Special command
                if (!handle_special_command(processor)) {
                    LOGW("Failed to process special command");
                }
                break;
            default:
                LOGI("Processing standard message");
                break;
        }
    }

    // Cleanup JSON objects
    if (processor->current_msg) {
        json_object_put(processor->current_msg);
        processor->current_msg = NULL;
    }

    // Cleanup message buffer if needed
    if (processor->needs_cleanup && processor->msg_buffer) {
        //SINK
        free(processor->msg_buffer);
        processor->msg_buffer = NULL;
        processor->needs_cleanup = false;
    }

    return true;
}

void
sc_device_msg_processor_destroy(struct sc_device_msg_processor *processor) {
    if (processor->msg_buffer) {
        free(processor->msg_buffer);
    }
    if (processor->config) {
        json_object_put(processor->config);
    }
    if (processor->current_msg) {
        json_object_put(processor->current_msg);
    }
} 