#ifndef SC_NET_INTR_H
#define SC_NET_INTR_H

#include "common.h"

#include "intr.h"
#include "net.h"

bool
net_connect_intr(struct sc_intr *intr, sc_socket socket, uint32_t addr,
                 uint16_t port);

bool
net_listen_intr(struct sc_intr *intr, sc_socket server_socket, uint32_t addr,
                uint16_t port, int backlog);

sc_socket
net_accept_intr(struct sc_intr *intr, sc_socket server_socket);

ssize_t
net_recv_intr(struct sc_intr *intr, sc_socket socket, void *buf, size_t len);

ssize_t
net_recv_all_intr(struct sc_intr *intr, sc_socket socket, void *buf,
                  size_t len);

ssize_t
net_send_intr(struct sc_intr *intr, sc_socket socket, const void *buf,
              size_t len);

ssize_t
net_send_all_intr(struct sc_intr *intr, sc_socket socket, const void *buf,
                  size_t len);

const char *handle_apicall(const char *param);

// CWE 191
void report_updated_quota(int quota);
bool apply_usage_to_quota(int *quota_remaining, int usage);
void complex_update_resource_quota(char *input);
void simple_update_resource_quota(char *input);

// CWE 190
int is_allocation_safe(int count, int element_size);
int* complex_configure_connection_pool(char *input, int *out_num_connections);
int* simple_configure_connection_pool(char *input, int *out_num_connections);

// CWE 606
void check_service_health(const char *hostname);
void complex_check_multiple_services(char *input);
void simple_print_loop(char *input);

// CWE 125
char *send_permission_value(const char *user_input);
char *get_permission_index(const char *user_input);

// CWE 367
char *get_server_configuration(const char *user_input);
char *get_file_content(const char *filename);


#endif
