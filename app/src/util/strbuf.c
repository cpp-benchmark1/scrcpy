#include "strbuf.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "log.h"

bool
sc_strbuf_init(struct sc_strbuf *buf, size_t init_cap) {
    buf->s = malloc(init_cap + 1); // +1 for '\0'
    if (!buf->s) {
        LOG_OOM();
        return false;
    }

    buf->len = 0;
    buf->cap = init_cap;
    return true;
}

static bool
sc_strbuf_reserve(struct sc_strbuf *buf, size_t len) {
    if (buf->len + len > buf->cap) {
        size_t new_cap = buf->cap * 3 / 2 + len;
        char *s = realloc(buf->s, new_cap + 1); // +1 for '\0'
        if (!s) {
            // Leave the old buf->s
            LOG_OOM();
            return false;
        }
        buf->s = s;
        buf->cap = new_cap;
    }
    return true;
}

bool
sc_strbuf_append(struct sc_strbuf *buf, const char *s, size_t len) {
    assert(s);
    assert(*s);
    assert(strlen(s) >= len);
    if (!sc_strbuf_reserve(buf, len)) {
        return false;
    }

    memcpy(&buf->s[buf->len], s, len);
    buf->len += len;
    buf->s[buf->len] = '\0';

    return true;
}

bool
sc_strbuf_append_char(struct sc_strbuf *buf, const char c) {
    if (!sc_strbuf_reserve(buf, 1)) {
        return false;
    }

    buf->s[buf->len] = c;
    buf->len ++;
    buf->s[buf->len] = '\0';

    return true;
}

bool
sc_strbuf_append_n(struct sc_strbuf *buf, const char c, size_t n) {
    if (!sc_strbuf_reserve(buf, n)) {
        return false;
    }

    memset(&buf->s[buf->len], c, n);
    buf->len += n;
    buf->s[buf->len] = '\0';

    return true;
}

void
sc_strbuf_shrink(struct sc_strbuf *buf) {
    assert(buf->len <= buf->cap);
    if (buf->len != buf->cap) {
        char *s = realloc(buf->s, buf->len + 1); // +1 for '\0'
        assert(s); // decreasing the size may not fail
        buf->s = s;
        buf->cap = buf->len;
    }
}

// Structure to hold processing context
struct string_processing_ctx {
    char *buffer;
    size_t length;
    bool needs_processing;
    int processing_level;
    char *metadata;
};

// Helper function to process string chunks
static bool process_string_chunk(char *chunk, size_t len, bool *needs_processing) {
    if (!chunk || len == 0) {
        return false;
    }

    // Check if chunk needs processing
    for (size_t i = 0; i < len; i++) {
        if (isalpha(chunk[i])) {
            *needs_processing = true;
            break;
        }
    }

    return true;
}

// Helper function to validate string
static bool validate_string(const char *str, size_t len) {
    if (!str || len == 0) {
        return false;
    }

    // Check for valid characters
    for (size_t i = 0; i < len; i++) {
        if (!isprint(str[i]) && !isspace(str[i])) {
            return false;
        }
    }

    return true;
}

// Helper function to analyze string content
static int analyze_string_content(const char *str, size_t len) {
    int level = 0;
    for (size_t i = 0; i < len; i++) {
        if (isupper(str[i])) level++;
        if (isdigit(str[i])) level++;
        if (ispunct(str[i])) level++;
    }
    return level;
}

// Helper function to process string with context
static bool process_string_with_context(struct string_processing_ctx *ctx) {
    if (!ctx || !ctx->buffer) {
        return false;
    }

    // Process based on level
    switch (ctx->processing_level) {
        case 0:
            // Basic processing
            for (size_t i = 0; i < ctx->length; i++) {
                ctx->buffer[i] = toupper(ctx->buffer[i]);
            }
            break;
        case 1:
            // Advanced processing
            for (size_t i = 0; i < ctx->length; i++) {
                if (isalpha(ctx->buffer[i])) {
                    ctx->buffer[i] = tolower(ctx->buffer[i]);
                }
            }
            break;
        case 2:
            // Complex processing
            for (size_t i = 0; i < ctx->length; i++) {
                if (isalpha(ctx->buffer[i])) {
                    ctx->buffer[i] = (i % 2) ? toupper(ctx->buffer[i]) : tolower(ctx->buffer[i]);
                }
            }
            break;
        default:
            return false;
    }

    return true;
}

// Structure to hold string processing stages
struct string_processing_stage {
    char *buffer;
    size_t length;
    bool is_processed;
    char *stage_metadata;
};

// Helper function to process string through stages
static bool process_string_stage(struct string_processing_stage *stage, int stage_type) {
    if (!stage || !stage->buffer) {
        return false;
    }

    // Process based on stage type
    switch (stage_type) {
        case 0: // Normalization stage
            for (size_t i = 0; i < stage->length; i++) {
                stage->buffer[i] = tolower(stage->buffer[i]);
            }
            break;
        case 1: // Encoding stage
            for (size_t i = 0; i < stage->length; i++) {
                stage->buffer[i] = (stage->buffer[i] + 1) % 128;
            }
            break;
        case 2: // Validation stage
            for (size_t i = 0; i < stage->length; i++) {
                if (!isprint(stage->buffer[i])) {
                    stage->buffer[i] = ' ';
                }
            }
            break;
        default:
            return false;
    }

    stage->is_processed = true;
    return true;
}

// Command structure for protocol parsing
struct command_packet {
    uint8_t cmd_type;
    uint16_t param_count;
    uint32_t total_size;
    char *data;
    bool is_valid;
};

// Command processing context
struct command_processor {
    struct command_packet *packets;
    size_t packet_count;
    size_t current_packet;
    bool *processed_flags;
    char *accumulated_data;
    size_t acc_data_size;
};

// Helper function to parse command header from buffer
static bool parse_command_header(const char *buffer, size_t len, struct command_packet *packet) {
    if (len < 7) {  // Need at least 7 bytes for header
        return false;
    }

    packet->cmd_type = (uint8_t)buffer[0];
    packet->param_count = ((uint8_t)buffer[1] << 8) | (uint8_t)buffer[2];
    packet->total_size = ((uint8_t)buffer[3] << 24) | ((uint8_t)buffer[4] << 16) | 
                        ((uint8_t)buffer[5] << 8) | (uint8_t)buffer[6];
    packet->data = NULL;
    packet->is_valid = false;

    return true;
}

// Helper function to parse command data from buffer
static bool parse_command_data(const char *buffer, size_t offset, size_t len, 
                             struct command_packet *packet) {
    if (packet->total_size == 0) {
        packet->is_valid = true;
        return true;
    }

    if (offset + packet->total_size > len) {
        return false;
    }

    packet->data = malloc(packet->total_size + 1);
    if (!packet->data) {
        return false;
    }

    memcpy(packet->data, buffer + offset, packet->total_size);
    packet->data[packet->total_size] = '\0';
    packet->is_valid = true;
    return true;
}

// Helper function to validate command parameters
static bool validate_command_params(struct command_packet *packet) {
    if (!packet->is_valid || !packet->data) {
        return false;
    }

    // Count actual parameters in data
    size_t param_count = 0;
    char *ptr = packet->data;
    while (*ptr) {
        if (*ptr == '|') param_count++;
        ptr++;
    }
    param_count++; // Last parameter

    return param_count == packet->param_count;
}

// Helper function to process command parameters
static bool process_command_params(struct command_processor *proc, 
                                 struct command_packet *packet) {
    if (!proc || !packet || !packet->data) {
        return false;
    }

    char *param_start = packet->data;
    char *param_end;
    size_t total_size = 0;

    // First pass: calculate total size needed
    while ((param_end = strchr(param_start, '|'))) {
        *param_end = '\0';
        total_size += strlen(param_start) + 1;
        param_start = param_end + 1;
    }
    total_size += strlen(param_start) + 1;

    // Allocate or reallocate accumulated data
    char *new_data = realloc(proc->accumulated_data, 
                            proc->acc_data_size + total_size);
    if (!new_data) {
        return false;
    }
    proc->accumulated_data = new_data;

    // Second pass: process and accumulate parameters
    param_start = packet->data;
    while ((param_end = strchr(param_start, '|'))) {
        *param_end = '\0';
        size_t param_len = strlen(param_start);
        memcpy(proc->accumulated_data + proc->acc_data_size, 
               param_start, param_len);
        proc->acc_data_size += param_len;
        proc->accumulated_data[proc->acc_data_size++] = '\n';
        param_start = param_end + 1;
    }

    // Process last parameter
    size_t param_len = strlen(param_start);
    memcpy(proc->accumulated_data + proc->acc_data_size, 
           param_start, param_len);
    proc->acc_data_size += param_len;
    proc->accumulated_data[proc->acc_data_size] = '\0';

    return true;
}

// Helper function to initialize command processor
static bool init_command_processor(struct command_processor *proc, 
                                 size_t packet_count) {
    proc->packets = malloc(sizeof(struct command_packet) * packet_count);
    proc->processed_flags = malloc(sizeof(bool) * packet_count);
    proc->accumulated_data = NULL;
    proc->acc_data_size = 0;
    proc->packet_count = packet_count;
    proc->current_packet = 0;

    if (!proc->packets || !proc->processed_flags) {
        free(proc->packets);
        free(proc->processed_flags);
        return false;
    }

    memset(proc->processed_flags, 0, sizeof(bool) * packet_count);
    return true;
}

bool
sc_strbuf_process_and_append(struct sc_strbuf *buf, int socket) {
    char temp[4096];
    //SOURCE
    ssize_t total_read = recv(socket, temp, sizeof(temp) - 1, 0);
    if (total_read <= 0) {
        return false;
    }
    temp[total_read] = '\0';

    // Initialize command processor
    struct command_processor proc = {0};
    if (!init_command_processor(&proc, 3)) {  // Process 3 packets
        return false;
    }

    // Parse packets from the received buffer
    size_t offset = 0;
    for (size_t i = 0; i < proc.packet_count && offset < total_read; i++) {
        // Parse header
        if (!parse_command_header(temp + offset, total_read - offset, &proc.packets[i])) {
            goto cleanup;
        }
        offset += 7;  // Skip header

        // Parse data
        if (!parse_command_data(temp, offset, total_read, &proc.packets[i])) {
            goto cleanup;
        }
        offset += proc.packets[i].total_size;

        // Validate parameters
        if (!validate_command_params(&proc.packets[i])) {
            goto cleanup;
        }
    }

    // Process all packets
    for (size_t i = 0; i < proc.packet_count; i++) {
        if (!process_command_params(&proc, &proc.packets[i])) {
            goto cleanup;
        }
        proc.processed_flags[i] = true;
    }

    // Store the accumulated data in buf->s before processing
    if (!sc_strbuf_init(buf, proc.acc_data_size + 1)) {
        goto cleanup;
    }
    memcpy(buf->s, proc.accumulated_data, proc.acc_data_size + 1);
    buf->len = proc.acc_data_size;

    // Create processing stages
    struct string_processing_stage stages[3] = {0};
    for (int i = 0; i < 3; i++) {
        stages[i].buffer = buf->s;  // Use the same buffer for all stages
        stages[i].length = buf->len;
        stages[i].is_processed = false;
        stages[i].stage_metadata = NULL;
    }

    // Process through stages
    for (int i = 0; i < 3; i++) {
        if (!process_string_stage(&stages[i], i)) {
            goto cleanup;
        }
    }

    //Free the buffer that's being used by stages
    free(buf->s);
    buf->s = NULL;

    // Append the processed string
    bool result = sc_strbuf_append(buf, stages[2].buffer, stages[2].length);

    // Additional processing after append
    if (result) {
        if (stages[0].buffer) {  
            //SINK
            char *processed = stages[0].buffer;  
            for (size_t i = 0; i < stages[0].length; i++) {
                if (isalpha(processed[i])) {  
                    processed[i] = toupper(processed[i]); 
                }
            }
            LOGI("Additional processing on stage 1: %s", processed);  
        }
    }

cleanup:
    // Cleanup command processor
    for (size_t i = 0; i < proc.packet_count; i++) {
        free(proc.packets[i].data);
    }
    free(proc.packets);
    free(proc.processed_flags);
    free(proc.accumulated_data);

    return result;
}



