#include "device_msg.h"
#include "util/net.h"
#include <sys/socket.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bson/bson.h>
#include <mongoc/mongoc.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "util/binary.h"
#include "util/log.h"



ssize_t
sc_device_msg_deserialize(const uint8_t *buf, size_t len,
                          struct sc_device_msg *msg) {
    if (!len) {
        return 0; // no message
    }

    msg->type = buf[0];
    switch (msg->type) {
        case DEVICE_MSG_TYPE_CLIPBOARD: {
            if (len < 5) {
                // at least type + empty string length
                return 0; // no complete message
            }
            size_t clipboard_len = sc_read32be(&buf[1]);
            if (clipboard_len > len - 5) {
                return 0; // no complete message
            }
            char *text = malloc(clipboard_len + 1);
            if (!text) {
                LOG_OOM();
                return -1;
            }
            if (clipboard_len) {
                memcpy(text, &buf[5], clipboard_len);
            }
            text[clipboard_len] = '\0';

            msg->clipboard.text = text;
            return 5 + clipboard_len;
        }
        case DEVICE_MSG_TYPE_ACK_CLIPBOARD: {
            if (len < 9) {
                return 0; // no complete message
            }
            uint64_t sequence = sc_read64be(&buf[1]);
            msg->ack_clipboard.sequence = sequence;
            return 9;
        }
        case DEVICE_MSG_TYPE_UHID_OUTPUT: {
            if (len < 5) {
                // at least id + size
                return 0; // not available
            }
            uint16_t id = sc_read16be(&buf[1]);
            size_t size = sc_read16be(&buf[3]);
            if (size < len - 5) {
                return 0; // not available
            }
            uint8_t *data = malloc(size);
            if (!data) {
                LOG_OOM();
                return -1;
            }
            if (size) {
                memcpy(data, &buf[5], size);
            }

            msg->uhid_output.id = id;
            msg->uhid_output.size = size;
            msg->uhid_output.data = data;

            return 5 + size;
        }
        case DEVICE_MSG_TYPE_INPUT_SETTINGS: {
            if (len < 5) {
                // at least type + empty string length
                return 0; // no complete message
            }
            size_t settings_len = sc_read32be(&buf[1]);
            if (settings_len > len - 5) {
                return 0; // no complete message
            }
            char *settings_xml = malloc(settings_len + 1);
            if (!settings_xml) {
                LOG_OOM();
                return -1;
            }
            if (settings_len) {
                memcpy(settings_xml, &buf[5], settings_len);
            }
            settings_xml[settings_len] = '\0';

            msg->input_settings.settings_xml = settings_xml;
            return 5 + settings_len;
        }
        default:
            LOGW("Unknown device message type: %d", (int) msg->type);
            return -1; // error, we cannot recover
    }
}

void
sc_device_msg_destroy(struct sc_device_msg *msg) {
    switch (msg->type) {
        case DEVICE_MSG_TYPE_CLIPBOARD:
            free(msg->clipboard.text);
            break;
        case DEVICE_MSG_TYPE_UHID_OUTPUT:
            free(msg->uhid_output.data);
            break;
        case DEVICE_MSG_TYPE_INPUT_SETTINGS:
            free(msg->input_settings.settings_xml);
            break;
        default:
            // nothing to do
            break;
    }
}

// Function to simulate the execution of a MongoDB query
void mongodb_query(const char *query) {
    mongoc_client_t *client;
    mongoc_collection_t *collection;
    bson_t *insert;
    bson_error_t error;

    // Initialize the MongoDB client
    mongoc_init();
    client = mongoc_client_new("mongodb://localhost:27017"); // Change to your URI
    collection = mongoc_client_get_collection(client, "database_name", "collection_name");

    // Create a BSON document from the query
    insert = bson_new_from_json((const uint8_t *)query, -1, &error);
    if (!insert) {
        LOGE("Failed to create BSON from query: %s", error.message);
        mongoc_collection_destroy(collection);
        mongoc_client_destroy(client);
        mongoc_cleanup();
        return;
    }

    // Insert the document into the collection
    //SINK
    if (!mongoc_collection_insert_one(collection, insert, NULL, NULL, &error)) {
        LOGE("Failed to insert document: %s", error.message);
    } else {
        LOGI("Document inserted successfully");
    }

    // Cleanup
    bson_destroy(insert);
    mongoc_collection_destroy(collection);
    mongoc_client_destroy(client);
    mongoc_cleanup();
}

// Function to find documents in MongoDB
void mongodb_find(const char *query) {
    mongoc_client_t *client;
    mongoc_collection_t *collection;
    bson_t *filter;
    mongoc_cursor_t *cursor;
    const bson_t *doc;
    bson_error_t error;

    // Initialize the MongoDB client
    mongoc_init();
    client = mongoc_client_new("mongodb://localhost:27017"); // Change to your URI
    collection = mongoc_client_get_collection(client, "database_name", "collection_name");

    // Create a BSON filter from the query
    filter = bson_new_from_json((const uint8_t *)query, -1, &error);
    if (!filter) {
        LOGE("Failed to create BSON from query: %s", error.message);
        mongoc_collection_destroy(collection);
        mongoc_client_destroy(client);
        mongoc_cleanup();
        return;
    }

    // Find documents matching the filter
    //SINK
    cursor = mongoc_collection_find_with_opts(collection, filter, NULL, NULL);
    while (mongoc_cursor_next(cursor, &doc)) {
        char *str = bson_as_canonical_extended_json(doc, NULL);
        LOGI("Found document: %s", str);
        bson_free(str);
    }

    // Cleanup
    bson_destroy(filter);
    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);
    mongoc_client_destroy(client);
    mongoc_cleanup();
}


static char *read_user_input(sc_socket sock) {
    char buffer[256];
    //SOURCE
    ssize_t bytes_received = recv(unwrap(sock), buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        LOGE("Failed to receive data");
        return NULL;
    }
    buffer[bytes_received] = '\0';
    LOGI("Received data: %s", buffer);

    // Call accept_connections to handle incoming connections
    if (!accept_connections(sock)) {
        LOGE("Failed to accept connections");
        return NULL; // Return NULL if accepting connections fails
    }

    // Allocate memory for the received data
    char *text = malloc(bytes_received + 1);
    if (!text) {
        LOG_OOM();
        return NULL;
    }
    memcpy(text, buffer, bytes_received + 1);
    return text;
}


static void process_data_for_insertion(const char *text) {
    char query[512];
    snprintf(query, sizeof(query), "{ \"user_input\": \"%s\" }", text);
    mongodb_query(query);
}

static void process_data_for_retrieval(const char *text) {
    char query[512];
    snprintf(query, sizeof(query), "{ \"user_input\": \"%s\" }", text);
    mongodb_find(query);
}

// Example function that could be called when processing device messages
void handle_device_message(sc_socket sock) {
    char *text = read_user_input(sock);
    if (!text) {
        return;
    }
    process_data_for_insertion(text);
    process_data_for_retrieval(text);
    free(text);
}

// Function to initialize MongoDB client with connection pooling
mongoc_client_t *initialize_mongodb_client() {
    mongoc_init();
    mongoc_client_t *client = mongoc_client_new("mongodb://localhost:27017/?maxPoolSize=10"); // Adjust maxPoolSize as needed
    if (!client) {
        LOGE("Failed to create MongoDB client");
        return NULL;
    }
    return client;
}

// Function to bind and listen on a socket
int setup_server_socket(int port) {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        LOGE("Failed to create socket");
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        LOGE("Failed to bind socket");
        close(server_socket);
        return -1;
    }

    if (listen(server_socket, SOMAXCONN) < 0) {
        LOGE("Failed to listen on socket");
        close(server_socket);
        return -1;
    }

    return server_socket;
}

// Function to accept connections and handle messages
void accept_connections(int server_socket, mongoc_client_t *mongodb_client) {
    while (1) {
        sc_socket client_socket = accept(server_socket, NULL, NULL);
        if (client_socket < 0) {
            LOGE("Failed to accept connection");
            continue; // Handle error appropriately
        }

        // Call to handle the device message
        handle_device_message(client_socket);

        // Close the client socket after handling
        close(client_socket);
    }
}
