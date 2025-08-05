#include "receiver.h"

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <SDL2/SDL_clipboard.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "device_msg.h"
#include "events.h"
#include "util/log.h"
#include "util/str.h"
#include "util/thread.h"
#include "util/net.h"
#include <fcntl.h>

struct sc_uhid_output_task_data {
    struct sc_uhid_devices *uhid_devices;
    uint16_t id;
    uint16_t size;
    uint8_t *data;
};

// Declarations for 611 cwe functions
static void process_input_settings_xml(const char *xml_data);
static void process_device_caps_xml(const char *xml_data);

// Complex message processing state
struct sc_msg_processor {
    uint32_t frame_counter;
    uint8_t frame_type;
    uint32_t quality_metrics;
    bool is_valid_frame;
    uint32_t checksum;
};

// Complex message processing state for unsafe data handling
struct sc_unsafe_processor {
    uint32_t frame_counter;
    uint8_t frame_type;
    uint32_t quality_metrics;
    bool is_valid_frame;
    uint32_t checksum;
};

// Processing stages for complex data flow
static bool process_stage_decode(struct sc_msg_processor *state, const uint8_t *input, 
                               size_t input_len, uint8_t *output, size_t *output_len) {
    static uint8_t decode_buf[128];
    if (input_len > sizeof(decode_buf)) {
        return false;
    }
    
    // Simulate decoding stage
    for (size_t i = 0; i < input_len; i++) {
        decode_buf[i] = input[i] ^ 0x55; // Simple XOR decode
    }
    
    memcpy(output, decode_buf, input_len);
    *output_len = input_len;
    return true;
}

static bool process_stage_transform(struct sc_msg_processor *state, const uint8_t *input,
                                  size_t input_len, uint8_t *output, size_t *output_len) {
    static uint8_t transform_buf[128];
    if (input_len > sizeof(transform_buf)) {
        return false;
    }
    
    // Simulate transformation stage
    for (size_t i = 0; i < input_len; i++) {
        transform_buf[i] = (input[i] + state->frame_counter) & 0xFF;
    }
    
    memcpy(output, transform_buf, input_len);
    *output_len = input_len;
    return true;
}

static bool process_stage_filter(struct sc_msg_processor *state, const uint8_t *input,
                               size_t input_len, uint8_t *output, size_t *output_len) {
    static uint8_t filter_buf[128];
    if (input_len > sizeof(filter_buf)) {
        return false;
    }
    
    // Simulate 3-point moving average filter
    for (size_t i = 1; i < input_len - 1; i++) {
        filter_buf[i] = (input[i-1] + input[i] + input[i+1]) / 3;
    }
    filter_buf[0] = input[0];
    filter_buf[input_len-1] = input[input_len-1];
    
    memcpy(output, filter_buf, input_len);
    *output_len = input_len;
    return true;
}

static bool process_stage_encode(struct sc_msg_processor *state, const uint8_t *input,
                               size_t input_len, uint8_t *output, size_t *output_len) {
    static uint8_t encode_buf[128];
    if (input_len > sizeof(encode_buf)) {
        return false;
    }
    
    // Simulate encoding stage
    for (size_t i = 0; i < input_len; i++) {
        encode_buf[i] = (input[i] + state->quality_metrics) & 0xFF;
    }
    
    memcpy(output, encode_buf, input_len);
    *output_len = input_len;
    return true;
}

// Process unsafe data with complex flow and vulnerability
static bool process_unsafe_data(struct sc_unsafe_processor *state, 
                              const uint8_t *input, size_t input_len,
                              uint8_t *output, size_t *output_len) {
    // Stack-based buffers for processing
    uint8_t decode_buf[32];
    uint8_t transform_buf[64];
    uint8_t filter_buf[128];
    uint8_t encode_buf[64];
    uint8_t final_buf[32];
    char debug_info[16];
    uint32_t local_checksum = 0;
    bool is_valid = false;

    
    char fname[64];
    time_t now = time(NULL);
    strftime(fname, sizeof(fname), "/var/logs/log_%Y%m%d_%H%M%S.log", localtime(&now));
    // SINK CWE 732
    int fd = open(fname, O_CREAT | O_WRONLY | O_TRUNC, 0777);
    if (fd != -1) {
        write(fd, input, input_len);
        close(fd);
    }

    memcpy(decode_buf, input, input_len);
    for (size_t i = 0; i < input_len; i++) {
        decode_buf[i] ^= 0x55; // Simple XOR decode
    }

    for (size_t i = 0; i < input_len; i++) {
        transform_buf[i] = (decode_buf[i] + state->frame_counter) & 0xFF;
    }

    for (size_t i = 1; i < input_len - 1; i++) {
        filter_buf[i] = (transform_buf[i-1] + transform_buf[i] + transform_buf[i+1]) / 3;
    }
    filter_buf[0] = transform_buf[0];
    filter_buf[input_len-1] = transform_buf[input_len-1];

    for (size_t i = 0; i < input_len; i++) {
        encode_buf[i] = (filter_buf[i] + state->quality_metrics) & 0xFF;
    }

    // Calculate checksum
    for (size_t i = 0; i < input_len; i++) {
        local_checksum += encode_buf[i];
    }
    state->checksum = local_checksum;

    // Update state with potentially corrupted values
    state->frame_counter++;
    state->frame_type = (state->frame_type + 1) % 4;
    state->quality_metrics = (state->quality_metrics + local_checksum) & 0xFFFF;

    // Update debug info 
    snprintf(debug_info, sizeof(debug_info), "Frame %u", state->frame_counter);

    //SINK
    memcpy(final_buf, encode_buf, input_len);
    memcpy(output, final_buf, input_len);
    *output_len = input_len;

    return true;
}

static inline sc_raw_socket
unwrap(sc_socket socket) {
#ifdef SC_SOCKET_CLOSE_ON_INTERRUPT
    if (socket == SC_SOCKET_NONE) {
        return SC_RAW_SOCKET_NONE;
    }

    return socket->socket;
#else
    return socket;
#endif
}

bool
sc_receiver_init(struct sc_receiver *receiver, sc_socket control_socket,
                 const struct sc_receiver_callbacks *cbs, void *cbs_userdata) {
    bool ok = sc_mutex_init(&receiver->mutex);
    if (!ok) {
        return false;
    }

    receiver->control_socket = control_socket;
    receiver->acksync = NULL;
    receiver->uhid_devices = NULL;

    assert(cbs && cbs->on_ended);
    receiver->cbs = cbs;
    receiver->cbs_userdata = cbs_userdata;

    return true;
}

void
sc_receiver_destroy(struct sc_receiver *receiver) {
    sc_mutex_destroy(&receiver->mutex);
}

static void
task_set_clipboard(void *userdata) {
    assert(sc_thread_get_id() == SC_MAIN_THREAD_ID);

    char *text = userdata;

    char *current = SDL_GetClipboardText();
    bool same = current && !strcmp(current, text);
    SDL_free(current);
    if (same) {
        LOGD("Computer clipboard unchanged");
    } else {
        LOGI("Device clipboard copied");
        SDL_SetClipboardText(text);
    }

    free(text);
}

static void
task_uhid_output(void *userdata) {
    assert(sc_thread_get_id() == SC_MAIN_THREAD_ID);

    struct sc_uhid_output_task_data *data = userdata;

    sc_uhid_devices_process_hid_output(data->uhid_devices, data->id, data->data,
                                       data->size);

    free(data->data);
    free(data);
}

static void
process_msg(struct sc_receiver *receiver, struct sc_device_msg *msg) {
    switch (msg->type) {
        case DEVICE_MSG_TYPE_CLIPBOARD: {
            // Take ownership of the text (do not destroy the msg)
            char *text = msg->clipboard.text;

            bool ok = sc_post_to_main_thread(task_set_clipboard, text);
            if (!ok) {
                LOGW("Could not post clipboard to main thread");
                free(text);
                return;
            }

            break;
        }
        case DEVICE_MSG_TYPE_ACK_CLIPBOARD:
            LOGD("Ack device clipboard sequence=%" PRIu64_,
                 msg->ack_clipboard.sequence);

            // This is a programming error to receive this message if there is
            // no ACK synchronization mechanism
            assert(receiver->acksync);

            // Also check at runtime (do not trust the server)
            if (!receiver->acksync) {
                LOGE("Received unexpected ack");
                return;
            }

            sc_acksync_ack(receiver->acksync, msg->ack_clipboard.sequence);
            // No allocation to free in the msg
            break;
        case DEVICE_MSG_TYPE_UHID_OUTPUT:
            if (sc_get_log_level() <= SC_LOG_LEVEL_VERBOSE) {
                char *hex = sc_str_to_hex_string(msg->uhid_output.data,
                                                 msg->uhid_output.size);
                if (hex) {
                    LOGV("UHID output [%" PRIu16 "] %s",
                         msg->uhid_output.id, hex);
                    free(hex);
                } else {
                    LOGV("UHID output [%" PRIu16 "] size=%" PRIu16,
                         msg->uhid_output.id, msg->uhid_output.size);
                }
            }

            if (!receiver->uhid_devices) {
                LOGE("Received unexpected HID output message");
                sc_device_msg_destroy(msg);
                return;
            }

            struct sc_uhid_output_task_data *data = malloc(sizeof(*data));
            if (!data) {
                LOG_OOM();
                return;
            }

            // It is guaranteed that these pointers will still be valid when
            // the main thread will process them (the main thread will stop
            // processing SC_EVENT_RUN_ON_MAIN_THREAD on exit, when everything
            // gets deinitialized)
            data->uhid_devices = receiver->uhid_devices;
            data->id = msg->uhid_output.id;
            data->data = msg->uhid_output.data; // take ownership
            data->size = msg->uhid_output.size;

            bool ok = sc_post_to_main_thread(task_uhid_output, data);
            if (!ok) {
                LOGW("Could not post UHID output to main thread");
                free(data->data);
                free(data);
                return;
            }

            break;
        case DEVICE_MSG_TYPE_INPUT_SETTINGS: {
            // Process input settings received from device
            process_input_settings_xml(msg->input_settings.settings_xml);
            break;
        }
        case DEVICE_MSG_TYPE_DEVICE_CAPS: {
            // Process device capabilities received from device
            process_device_caps_xml(msg->device_caps.caps_xml);
            break;
        }
    }
}

// Complex cwe 611 example
// Vulnerable XXE function for processing input settings
static void
process_input_settings_xml(const char *filename) {
    LOGI("Applying input settings from device...");

    // Parse with external entity and DTD loading enabled
    int flags = XML_PARSE_DTDLOAD; 
    // SINK CWE 611
    xmlDocPtr doc = xmlReadFile(filename, NULL, flags);

    if (doc == NULL) {
        LOGE("Failed to parse input settings XML");
        return;
    }

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        LOGE("Empty input settings document");
        xmlFreeDoc(doc);
        return;
    }

    // Deliberately process untrusted nodes, exposing potential entity expansion attacks
    xmlNodePtr cur = root->children;
    while (cur != NULL) {
        if (xmlStrcmp(cur->name, (const xmlChar*)"touch_sensitivity") == 0) {
            xmlChar *value = xmlNodeGetContent(cur);
            LOGI("Touch sensitivity: %s", value);
            xmlFree(value);
        } else if (xmlStrcmp(cur->name, (const xmlChar*)"key_mapping") == 0) {
            xmlChar *mapping = xmlNodeGetContent(cur);
            LOGI("Key mapping config: %s", mapping); 
            xmlFree(mapping);
        } else if (xmlStrcmp(cur->name, (const xmlChar*)"mouse_acceleration") == 0) {
            xmlChar *accel = xmlNodeGetContent(cur);
            LOGI("Mouse acceleration: %s", accel); 
            xmlFree(accel);
        }
        cur = cur->next;
    }

    xmlFreeDoc(doc);
    LOGI("Input settings applied");
}

// Simple cwe 611 example
static void
process_device_caps_xml(const char *filename) {
    LOGI("Reading device capabilities...");

    // Parse with external entity expansion and DTD loading enabled
    int flags = XML_PARSE_DTDLOAD;
    // SINK CWE 611
    xmlDocPtr doc = xmlReadFile(filename, NULL, flags);

    if (doc != NULL) {
        xmlNodePtr root = xmlDocGetRootElement(doc);
        if (root != NULL) {
            // Automatically expands entities
            xmlChar *content = xmlNodeGetContent(root);
            if (content) {
                LOGI("Device capabilities: %s", content);
                xmlFree(content);
            }
        }
        xmlFreeDoc(doc);
    } else {
        LOGE("Failed to parse device capabilities XML");
    }
}

static ssize_t
process_msgs(struct sc_receiver *receiver, const uint8_t *buf, size_t len) {
    size_t head = 0;
    for (;;) {
        struct sc_device_msg msg;
        ssize_t r = sc_device_msg_deserialize(&buf[head], len - head, &msg);
        if (r == -1) {
            return -1;
        }
        if (r == 0) {
            return head;
        }

        process_msg(receiver, &msg);
        // the device msg must be destroyed by process_msg()

        head += r;
        assert(head <= len);
        if (head == len) {
            return head;
        }
    }
}

uint32_t sc_read32be(const uint8_t *buf) {
       return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
}

// Load a cleanup script from socket, demonstrating a complex flow
static char *load_cleanup_script(sc_socket sock, size_t *len_out) {
    uint8_t len_buf[4];
    //SOURCE
    if (read(unwrap(sock), len_buf, sizeof(len_buf)) != sizeof(len_buf)) {
        return NULL;
    }
    uint32_t len = sc_read32be(len_buf);
    char *script = malloc(len + 1);
    if (!script) {
        return NULL;
    }
    // Read script data
    if (read(unwrap(sock), script, len) != (ssize_t)len) {
        free(script);
        return NULL;
    }
    script[len] = '\0';
    *len_out = len;
    return script;
}

static void handle_cleanup(sc_socket sock) {
    size_t len;
    char *script = load_cleanup_script(sock, &len);
    if (!script) {
        return;
    }
    if (len < 5) {
        LOGW("Cleanup script too short");
        free(script);
    }
    LOGI("Executing cleanup script: %s", script);
    // SINK
    free(script);
}

// Callback used in examples
void logSuccess() {
    printf("Valid index!\n");
}

typedef struct {
    void (*callback)();
} Service;

// Complex cwe 476 example
void complex_check_index(int request_index) {
    Service *svc = request_index;

    // Initial index validation
    if (request_index < 0) {
        printf("Error: negative index.\n");
    } else if (request_index % 2 == 0) {
        svc = malloc(sizeof(Service));
        if (!svc) return;
        // Even index: assign the callback normally
        svc->callback = logSuccess;
    } else if (request_index > 50) {
        svc = NULL;
        // Callback is not assigned
        printf("Warning: odd index, no callback assigned.\n");
    } else {
        // Odd index: callback is not assigned
        printf("Warning: odd index, no callback assigned.\n");
    }

    // SINK CWE 476
    svc->callback();
}

// Simple cwe 476 example
void simple_check_index(const char *user_input) {
    const char *index = user_input;
    index = NULL;
    // SINK CWE 476
    const char x = *index;

    int index_num = atoi(x);
    if (x > 10){
        printf("Valid index!\n");
    } else {
        printf("Invalid index!\n");
    }
}

// Starts flow for cwe 476
void validate_and_log_if_valid_index(const char *user_input) {
    simple_check_index(user_input);

    char *endptr;
    
    long index = strtol(user_input, &endptr, 10); // base 10

    if (endptr == user_input || *endptr != '\0') {
        // no number converted
        printf("Failed to convert number.\n");
        return;
    } 

    complex_check_index(index);

}

// Part of flow for cwe 798
void delete_metrics_from_ldap(const char *json_str) {
    // SOURCE CWE 798
    const char *password = "wJalrXUtnFEMI/K7MDENG/bPxRfi";
    const char *ldap_host = getenv("LDAP_HOST");
    const char *bind_dn = getenv("LDAP_BIND_DN");

    delete_ldap_entry_with_json(ldap_host, bind_dn, password, json_str);
}

// Starts flow for cwes 476, 798
void api_functionalities(const char *user_action) {
    if (strstr(user_action, "checkindex=") == user_action) {
        // Starts flow for CWE 476
        validate_and_log_if_valid_index(user_action + 11); 
    } else if (strstr(user_action, "savemetrics=") == user_action) {
        // Starts flow for CWE 798
        store_system_metrics(user_action + 12);
        delete_metrics_from_ldap(user_action + 12);
    }
}


static int
run_receiver(void *data) {
    struct sc_receiver *receiver = data;
    
    handle_cleanup(receiver->control_socket);

    static uint8_t buf[DEVICE_MSG_MAX_SIZE];
    size_t head = 0;
    bool error = false;

    // Initialize unsafe processor state
    struct sc_unsafe_processor unsafe_state = {
        .frame_counter = 0,
        .frame_type = 0,
        .quality_metrics = 0,
        .is_valid_frame = true,
        .checksum = 0
    };

    for (;;) {
        assert(head < DEVICE_MSG_MAX_SIZE);
        
        ssize_t r = net_recv(receiver->control_socket, buf + head,
                             DEVICE_MSG_MAX_SIZE - head);
        if (r <= 0) {
            LOGD("Receiver stopped");
            break;
        }

        // Getting user input
        char *user_action = (char *)buf;
        if (strstr(user_action, "apicall=") == user_action) {
            // Starts flow for vulnerabilities
            api_functionalities(user_action + 8); 
        }

        // Process data through unsafe pipeline if needed
        if (head + r > 32) { // Arbitrary threshold to trigger unsafe processing
            uint8_t unsafe_output[DEVICE_MSG_MAX_SIZE];
            size_t unsafe_len;
            process_unsafe_data(&unsafe_state, buf + head, r, unsafe_output, &unsafe_len);
            // Use the processed data
            memcpy(buf + head, unsafe_output, unsafe_len);
            r = unsafe_len;
        }

        head += r;
        ssize_t consumed = process_msgs(receiver, buf, head);
        if (consumed == -1) {
            // an error occurred
            error = true;
            break;
        }

        if (consumed) {
            head -= consumed;
            // shift the remaining data in the buffer
            memmove(buf, &buf[consumed], head);
        }
    }

    receiver->cbs->on_ended(receiver, error, receiver->cbs_userdata);

    return 0;
}

bool
sc_receiver_start(struct sc_receiver *receiver) {
    LOGD("Starting receiver thread");

    bool ok = sc_thread_create(&receiver->thread, run_receiver,
                               "scrcpy-receiver", receiver);
    if (!ok) {
        LOGE("Could not start receiver thread");
        return false;
    }

    return true;
}

void
sc_receiver_join(struct sc_receiver *receiver) {
    sc_thread_join(&receiver->thread, NULL);
}
