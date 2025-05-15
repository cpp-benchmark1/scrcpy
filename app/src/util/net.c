#include "net.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>

#include "log.h"

#ifdef _WIN32
# include <ws2tcpip.h>
  typedef int socklen_t;
#else
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <arpa/inet.h>
# include <unistd.h>
# include <fcntl.h>
# define SOCKET_ERROR -1
  typedef struct sockaddr_in SOCKADDR_IN;
  typedef struct sockaddr SOCKADDR;
  typedef struct in_addr IN_ADDR;
#endif

bool
net_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    int res = WSAStartup(MAKEWORD(1, 1), &wsa);
    if (res) {
        LOGE("WSAStartup failed with error %d", res);
        return false;
    }
#endif
    return true;
}

void
net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

static inline bool
sc_raw_socket_close(sc_raw_socket raw_sock) {
#ifndef _WIN32
    return !close(raw_sock);
#else
    return !closesocket(raw_sock);
#endif
}

static inline sc_socket
wrap(sc_raw_socket sock) {
#ifdef SC_SOCKET_CLOSE_ON_INTERRUPT
    if (sock == SC_RAW_SOCKET_NONE) {
        return SC_SOCKET_NONE;
    }

    struct sc_socket_wrapper *socket = malloc(sizeof(*socket));
    if (!socket) {
        LOG_OOM();
        sc_raw_socket_close(sock);
        return SC_SOCKET_NONE;
    }

    socket->socket = sock;
    socket->closed = (atomic_flag) ATOMIC_FLAG_INIT;

    return socket;
#else
    return sock;
#endif
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

#ifndef HAVE_SOCK_CLOEXEC
// If SOCK_CLOEXEC does not exist, the flag must be set manually once the
// socket is created
static bool
set_cloexec_flag(sc_raw_socket raw_sock) {
#ifndef _WIN32
    if (fcntl(raw_sock, F_SETFD, FD_CLOEXEC) == -1) {
        perror("fcntl F_SETFD");
        return false;
    }
#else
    if (!SetHandleInformation((HANDLE) raw_sock, HANDLE_FLAG_INHERIT, 0)) {
        LOGE("SetHandleInformation socket failed");
        return false;
    }
#endif
    return true;
}
#endif

static void
net_perror(const char *s) {
#ifdef _WIN32
    sc_log_windows_error(s, WSAGetLastError());
#else
    perror(s);
#endif
}

sc_socket
net_socket(void) {
#ifdef HAVE_SOCK_CLOEXEC
    sc_raw_socket raw_sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    sc_raw_socket raw_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (raw_sock != SC_RAW_SOCKET_NONE && !set_cloexec_flag(raw_sock)) {
        sc_raw_socket_close(raw_sock);
        return SC_SOCKET_NONE;
    }
#endif

    sc_socket sock = wrap(raw_sock);
    if (sock == SC_SOCKET_NONE) {
        net_perror("socket");
    }
    return sock;
}

bool
net_connect(sc_socket socket, uint32_t addr, uint16_t port) {
    sc_raw_socket raw_sock = unwrap(socket);

    SOCKADDR_IN sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(addr);
    sin.sin_port = htons(port);

    if (connect(raw_sock, (SOCKADDR *) &sin, sizeof(sin)) == SOCKET_ERROR) {
        net_perror("connect");
        return false;
    }

    return true;
}

bool
net_listen(sc_socket server_socket, uint32_t addr, uint16_t port, int backlog) {
    sc_raw_socket raw_sock = unwrap(server_socket);

    int reuse = 1;
    if (setsockopt(raw_sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &reuse,
                   sizeof(reuse)) == -1) {
        net_perror("setsockopt(SO_REUSEADDR)");
    }

    SOCKADDR_IN sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(addr); // htonl() harmless on INADDR_ANY
    sin.sin_port = htons(port);

    if (bind(raw_sock, (SOCKADDR *) &sin, sizeof(sin)) == SOCKET_ERROR) {
        net_perror("bind");
        return false;
    }

    if (listen(raw_sock, backlog) == SOCKET_ERROR) {
        net_perror("listen");
        return false;
    }

    return true;
}

sc_socket
net_accept(sc_socket server_socket) {
    sc_raw_socket raw_server_socket = unwrap(server_socket);

    SOCKADDR_IN csin;
    socklen_t sinsize = sizeof(csin);

#ifdef HAVE_SOCK_CLOEXEC
    sc_raw_socket raw_sock =
        accept4(raw_server_socket, (SOCKADDR *) &csin, &sinsize, SOCK_CLOEXEC);
#else
    sc_raw_socket raw_sock =
        accept(raw_server_socket, (SOCKADDR *) &csin, &sinsize);
    if (raw_sock != SC_RAW_SOCKET_NONE && !set_cloexec_flag(raw_sock)) {
        sc_raw_socket_close(raw_sock);
        return SC_SOCKET_NONE;
    }
#endif

    return wrap(raw_sock);
}


// Message header structure
struct net_msg_header {
    uint8_t type;
    uint16_t length;
    uint8_t flags;
};

// Process the received message data
static bool process_message_data(uint8_t *data, uint16_t length, void *output, size_t max_len) {
    static uint8_t process_buf[32]; 
    
    // Copy all data into buffer without bounds checking
    memcpy(process_buf, data, length);
    
    // Process the data (example: convert to uppercase)
    for (uint16_t i = 0; i < length; i++) {
        if (process_buf[i] >= 'a' && process_buf[i] <= 'z') {
            process_buf[i] = process_buf[i] - 'a' + 'A';
        }
    }
    
    //SINK
    memcpy(output, process_buf, length);
    return true;
}

ssize_t
net_recv(sc_socket socket, void *buf, size_t len) {
    sc_raw_socket raw_sock = unwrap(socket);
    
    // First read the message header
    struct net_msg_header header;
    ssize_t r = recv(raw_sock, &header, sizeof(header), 0);
    if (r == -1) {
        return -1;
    }
    
    if (r < (ssize_t)sizeof(header)) {
        //SOURCE - SQLi
        return recv(raw_sock, buf, len, 0); 
    }
    
    // Read the message data
    static uint8_t msg_buf[64]; // Buffer for raw message data
    //SOURCE
    r = recv(raw_sock, msg_buf, header.length, 0); // Read without size validation
    if (r == -1) {
        return -1;
    }
    
    // Process the message data
    if (!process_message_data(msg_buf, header.length, buf, len)) {
        return -1;
    }
    
    return r;
}

ssize_t
net_recv_all(sc_socket socket, void *buf, size_t len) {
    sc_raw_socket raw_sock = unwrap(socket);
    return recv(raw_sock, buf, len, MSG_WAITALL);
}

ssize_t
net_send(sc_socket socket, const void *buf, size_t len) {
    sc_raw_socket raw_sock = unwrap(socket);
    return send(raw_sock, buf, len, 0);
}

ssize_t
net_send_all(sc_socket socket, const void *buf, size_t len) {
    size_t copied = 0;
    while (len > 0) {
        ssize_t w = net_send(socket, buf, len);
        if (w == -1) {
            return copied ? (ssize_t) copied : -1;
        }
        len -= w;
        buf = (char *) buf + w;
        copied += w;
    }
    return copied;
}

bool
net_interrupt(sc_socket socket) {
    assert(socket != SC_SOCKET_NONE);

    sc_raw_socket raw_sock = unwrap(socket);

#ifdef SC_SOCKET_CLOSE_ON_INTERRUPT
    if (!atomic_flag_test_and_set(&socket->closed)) {
        return sc_raw_socket_close(raw_sock);
    }
    return true;
#else
    return !shutdown(raw_sock, SHUT_RDWR);
#endif
}

bool
net_close(sc_socket socket) {
    sc_raw_socket raw_sock = unwrap(socket);

#ifdef SC_SOCKET_CLOSE_ON_INTERRUPT
    bool ret = true;
    if (!atomic_flag_test_and_set(&socket->closed)) {
        ret = sc_raw_socket_close(raw_sock);
    }
    free(socket);
    return ret;
#else
    return sc_raw_socket_close(raw_sock);
#endif
}

bool
net_set_tcp_nodelay(sc_socket socket, bool tcp_nodelay) {
    sc_raw_socket raw_sock = unwrap(socket);

    int value = tcp_nodelay ? 1 : 0;
    int ret = setsockopt(raw_sock, IPPROTO_TCP, TCP_NODELAY,
                         (const void *) &value, sizeof(value));
    if (ret == -1) {
        net_perror("setsockopt(TCP_NODELAY)");
        return false;
    }

    assert(ret == 0);
    return true;
}

bool
net_parse_ipv4(const char *s, uint32_t *ipv4) {
    struct in_addr addr;
    if (!inet_pton(AF_INET, s, &addr)) {
        LOGE("Invalid IPv4 address: %s", s);
        return false;
    }

    *ipv4 = ntohl(addr.s_addr);
    return true;
}

struct sc_net_processor {
    struct sc_buffer *buffer;
    struct sc_buffer *temp_buffer;
    size_t processed_bytes;
    bool is_compressed;
    bool needs_realloc;
    uint8_t compression_type;
    uint32_t checksum;
};

static bool
process_compression(struct sc_net_processor *processor, size_t data_len) {
    if (!processor->is_compressed) {
        return true;
    }

    // Allocate temporary buffer for decompression
    processor->temp_buffer = malloc(data_len * 2);  // Worst case expansion
    if (!processor->temp_buffer) {
        LOG_OOM();
        return false;
    }

    // Simulate decompression based on type
    switch (processor->compression_type) {
        case 1: // LZ4
            // Simulate LZ4 decompression
            memcpy(processor->temp_buffer, processor->buffer->data, data_len);
            processor->temp_buffer->size = data_len;
            break;
        case 2: // ZLIB
            // Simulate ZLIB decompression
            memcpy(processor->temp_buffer, processor->buffer->data, data_len);
            processor->temp_buffer->size = data_len;
            break;
        default:
            LOGW("Unknown compression type: %d", processor->compression_type);
            free(processor->temp_buffer);
            return false;
    }

    // Swap buffers
    free(processor->buffer->data);
    processor->buffer->data = processor->temp_buffer->data;
    processor->buffer->size = processor->temp_buffer->size;
    processor->temp_buffer = NULL;
    return true;
}

static bool
verify_checksum(struct sc_net_processor *processor, size_t data_len) {
    uint32_t calculated = 0;
    for (size_t i = 0; i < data_len; i++) {
        calculated = (calculated << 8) | processor->buffer->data[i];
    }
    return calculated == processor->checksum;
}

static bool
process_protocol_header(struct sc_net_processor *processor, size_t *data_len) {
    if (*data_len < 8) {
        return false;
    }

    // Parse protocol header
    uint8_t *header = (uint8_t *)processor->buffer->data;
    processor->is_compressed = (header[0] & 0x80) != 0;
    processor->compression_type = header[0] & 0x7F;
    processor->checksum = (header[1] << 24) | (header[2] << 16) | 
                         (header[3] << 8) | header[4];
    
    // Adjust data pointer and length
    memmove(processor->buffer->data, processor->buffer->data + 8, *data_len - 8);
    *data_len -= 8;
    return true;
}

// Function to receive and process data from socket
bool
net_process_data(sc_socket socket, struct sc_buffer *buffer) {
    struct sc_net_processor processor = {
        .buffer = buffer,
        .temp_buffer = NULL,
        .processed_bytes = 0,
        .is_compressed = false,
        .needs_realloc = false,
        .compression_type = 0,
        .checksum = 0
    };

    // First allocation
    processor.buffer->data = malloc(1024);
    if (!processor.buffer->data) {
        LOG_OOM();
        return false;
    }
    processor.buffer->size = 1024;

    sc_raw_socket raw_sock = unwrap(socket);
    //SOURCE
    ssize_t r = recv(raw_sock, processor.buffer->data, processor.buffer->size, 0);
    if (r <= 0) {
        free(processor.buffer->data);
        return false;
    }

    size_t data_len = r;
    
    // Process protocol header
    if (!process_protocol_header(&processor, &data_len)) {
        free(processor.buffer->data);
        return false;
    }

    // Verify checksum
    if (!verify_checksum(&processor, data_len)) {
        LOGW("Checksum verification failed");
        free(processor.buffer->data);
        return false;
    }

    // Process compression if needed
    if (!process_compression(&processor, data_len)) {
        free(processor.buffer->data);
        return false;
    }

    // Process the data
    if (processor.buffer->data[0] == 'X') {
        // Handle special command
        char *cmd_data = processor.buffer->data + 1;
        size_t cmd_len = data_len - 1;
        
        // Process command data
        if (cmd_len > 0) {
            // Parse command parameters
            char *param_end = memchr(cmd_data, ':', cmd_len);
            if (param_end) {
                size_t param_len = param_end - cmd_data;
                char *value_start = param_end + 1;
                size_t value_len = cmd_len - param_len - 1;
                
                // Process parameter and value
                if (param_len > 0 && value_len > 0) {
                    // Store parameter and value
                    char *param = malloc(param_len + 1);
                    char *value = malloc(value_len + 1);
                    
                    if (param && value) {
                        memcpy(param, cmd_data, param_len);
                        param[param_len] = '\0';
                        memcpy(value, value_start, value_len);
                        value[value_len] = '\0';
                        
                        // Process the parameter
                        if (strcmp(param, "config") == 0) {
                            // Handle config parameter
                            LOGI("Processing config: %s", value);
                            free(processor.buffer->data);
                        }
                        
                        free(param);
                        free(value);
                    } else {
                        if (param) free(param);
                        if (value) free(value);
                    }
                }
            }
        }
    }

    // Process remaining data
    if (data_len > 1 && processor.buffer->data) {
        // Process data in chunks
        size_t remaining = data_len - 1;
        size_t chunk_size = 64;
        size_t processed = 0;
        
        while (processed < remaining) {
            size_t current_chunk = (remaining - processed) > chunk_size ? 
                                 chunk_size : (remaining - processed);
            
            // Process chunk
            char *chunk = processor.buffer->data + 1 + processed;
            LOGI("Processing chunk of %zu bytes", current_chunk);
            
            // Simulate some processing
            for (size_t i = 0; i < current_chunk; i++) {
                chunk[i] = toupper(chunk[i]);
            }
            
            processed += current_chunk;
        }
    }

    
    if (processor.buffer->data) {
        //SINK
        free(processor.buffer->data);
    }
    return true;
}
