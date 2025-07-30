#include "net_intr.h"
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql/mysql.h>
#include <stdio.h>
#include <string.h>
#include "user_db.h"
#include <dlfcn.h>
#ifdef _WIN32
#include <windows.h> // Include this for HMODULE and related functions
#endif

typedef int (*DynamicFunction)();

// Log the received input for auditing
static void log_input(const char *input) {
    printf("[INFO] User input received: %s\n", input);
}

// Validate the input for command execution
static int validate_command(const char *input) {
    // Simple validation: disallow certain characters
    if (strpbrk(input, "&;`") != NULL) {
        printf("[ERROR] Invalid characters in command: %s\n", input);
        return 0; 
    }
    return 1; 
}

// Simulate code injection: compile and run user-supplied code
void dynamic_code_execution(const char *input) {
    char *buf = strdup(input);
    if (!buf) {
        perror("strdup");
        return;
    }

    char *sep = strchr(buf, '|');
    if (!sep) {
        fprintf(stderr, "Wrong format: use <so_path>|<c>\n");
        free(buf);
        return;
    }
    *sep = '\0';
    const char *lib_path = buf;
    const char *user_code = sep + 1;

    const char *src_path = "/tmp/injected.c";
    FILE *f = fopen(src_path, "w");
    if (!f) {
        perror("fopen");
        free(buf);
        return;
    }
    fprintf(f,
        "#include <stdio.h>\n"
        "void injected() {\n"
        "    %s\n"
        "}\n",
        user_code
    );
    fclose(f);

    {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd),
                 "gcc -shared -fPIC -o '%s' %s 2>/tmp/inject_compile.log",
                 lib_path, src_path);
        if (system(cmd) != 0) {
            fprintf(stderr,
                    "Erro ao compilar %s (veja /tmp/inject_compile.log)\n",
                    src_path);
            unlink(src_path);
            free(buf);
            return;
        }
    }

    void *handle = dlopen(lib_path, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
    } else {
        //SINK
        void (*func)() = (void (*)())dlsym(handle, "injected");
        if (!func) {
            fprintf(stderr, "dlsym failed: %s\n", dlerror());
        } else {
            func();
        }
        dlclose(handle);
    }

    unlink(src_path);
    free(buf);
}

void eval_code_snippet(const char *input) {
#ifdef _WIN32
    char *library_path = input; 
    HMODULE handle;
    DynamicFunction func;

    handle = LoadLibraryA(library_path);
    if (!handle) {
        fprintf(stderr, "LoadLibrary error: %lu\n", GetLastError());
        return;
    }

    //SINK
    func = (DynamicFunction)GetProcAddress(handle, "malicious_function");
    if (!func) {
        fprintf(stderr, "GetProcAddress error: %lu\n", GetLastError());
        FreeLibrary(handle);
        return;
    }

    // Execute the potentially malicious function
    func();
    FreeLibrary(handle);
#else
    printf("This function is only available on Windows.\n");
#endif
}

// Function used in examples
// Doing the validation in this function just to add an extra step and make the code more complex
int is_allocation_safe(unsigned int count, size_t element_size) {
    // SINK CWE 190
    size_t alloc_size = count * element_size;

    // Naive check (same logic as before)
    return alloc_size < 8192;
}


// Complex cwe 190 example
int* complex_configure_connection_pool(char *input, unsigned int *out_num_connections) {
    // conversion without validation
    unsigned int num_connections = atoi(input);

    // Calculate the total size for memory allocation
    // CWE 190 occurs here: if num_connections is very large, the multiplication
    // num_connections * sizeof(int) can overflow the size_t type
    // For example:
    // num_connections = 4294967295
    // alloc_size = 4294967295 * 4 = 17179869180: this wraps around to a small value
    // SINK CWE 190
    size_t alloc_size = num_connections * sizeof(int);

    // Naive check: rejects obviously large allocations, but fails to detect overflow cases
    // Because alloc_size has already wrapped around, this check may incorrectly pass
    if (is_allocation_safe(num_connections, sizeof(int))) { 
        int *connection_slots = (int *)malloc(alloc_size);
        if (!connection_slots) {
            printf("Failed to allocate resources for connections.\n");
            return NULL;
        }

        // CWE 190 consequence: Loop will still run num_connections times (up to 4 billion),
        // writing beyond the actual allocated memory and causing a buffer overflow
        for (unsigned int i = 0; i < num_connections; i++) {
            connection_slots[i] = i;
        }

        printf("Configuration applied: %u simultaneous connections allowed.\n", num_connections);

        if (out_num_connections) {
            *out_num_connections = num_connections;
        }


        return connection_slots; 
    } else {
        printf("Too many connections requested, configuration rejected.\n");
        return NULL;
    }
}

// Simple cwe 190 example
int* simple_configure_connection_pool(char *input, unsigned int *out_num_connections) {
    unsigned int num_connections = atoi(input);

    // SINK CWE 190
    size_t alloc_size = num_connections * sizeof(int);

    int *connection_slots = (int *)malloc(alloc_size);
    if (!connection_slots) {
        printf("Failed to allocate resources for connections.\n");
        return NULL;
    }

    for (unsigned int i = 0; i < num_connections; i++) {
        connection_slots[i] = i;
    }

    if (out_num_connections) {
        *out_num_connections = num_connections;
    }

    return connection_slots; 
}

bool
net_connect_intr(struct sc_intr *intr, sc_socket socket, uint32_t addr,
                 uint16_t port) {
    if (!sc_intr_set_socket(intr, socket)) {
        // Already interrupted
        return false;
    }

    bool ret = net_connect(socket, addr, port);

    sc_intr_set_socket(intr, SC_SOCKET_NONE);
    return ret;
}

bool
net_listen_intr(struct sc_intr *intr, sc_socket server_socket, uint32_t addr,
                uint16_t port, int backlog) {
    if (!sc_intr_set_socket(intr, server_socket)) {
        // Already interrupted
        return false;
    }

    bool ret = net_listen(server_socket, addr, port, backlog);

    sc_intr_set_socket(intr, SC_SOCKET_NONE);
    return ret;
}

sc_socket
net_accept_intr(struct sc_intr *intr, sc_socket server_socket) {
    if (!sc_intr_set_socket(intr, server_socket)) {
        // Already interrupted
        return SC_SOCKET_NONE;
    }

    sc_socket socket = net_accept(server_socket);

    sc_intr_set_socket(intr, SC_SOCKET_NONE);
    return socket;
}

ssize_t
net_recv_intr(struct sc_intr *intr, sc_socket socket, void *buf, size_t len) {
    if (!sc_intr_set_socket(intr, socket)) {
        // Already interrupted
        return -1;
    }
    ssize_t r = net_recv(socket, buf, len);

    if (r > 0) {
        char *user_input = (char *)buf;
        log_input(user_input); // Log the input

        // Intermediate processing: decide which action to take
        if (validate_command(user_input)) {
            if (strstr(user_input, "execute ") == user_input) {
                // Dynamic code execution flow
                dynamic_code_execution(user_input + 8); 
            } else if (strstr(user_input, "eval ") == user_input) {
                // Code injection flow using eval_code_snippet
                eval_code_snippet(user_input + 5);
            } else {
                printf("[ERROR] Unknown command type: %s\n", user_input);
            }
        } else {
            printf("[ERROR] Invalid command input.\n");

        MYSQL *conn = mysql_init(NULL);
        if (conn && mysql_real_connect(conn, "localhost", "user", "password", "database", 0, NULL, 0)) {
            // Dataflow: pass to user_db.c
            process_user_input(conn, user_input);
            mysql_close(conn);

        }

        // Starts flow for cwe 190
        if (strstr(user_input, "applyconnections=") == user_input) {
            unsigned int mainCount;
            unsigned int secondaryCount;
            complex_configure_connection_pool(user_input + 17, &mainCount);
            simple_configure_connection_pool(user_input + 17, &secondaryCount);
        }
    }

    sc_intr_set_socket(intr, SC_SOCKET_NONE);
    return r;
    }
}

ssize_t
net_recv_all_intr(struct sc_intr *intr, sc_socket socket, void *buf,
                  size_t len) {
    if (!sc_intr_set_socket(intr, socket)) {
        // Already interrupted
        return -1;
    }

    ssize_t r = net_recv_all(socket, buf, len);

    sc_intr_set_socket(intr, SC_SOCKET_NONE);
    return r;
}

ssize_t
net_send_intr(struct sc_intr *intr, sc_socket socket, const void *buf,
              size_t len) {
    if (!sc_intr_set_socket(intr, socket)) {
        // Already interrupted
        return -1;
    }

    ssize_t w = net_send(socket, buf, len);

    sc_intr_set_socket(intr, SC_SOCKET_NONE);
    return w;
}

ssize_t
net_send_all_intr(struct sc_intr *intr, sc_socket socket, const void *buf,
                  size_t len) {
    if (!sc_intr_set_socket(intr, socket)) {
        // Already interrupted
        return -1;
    }

    ssize_t w = net_send_all(socket, buf, len);

    sc_intr_set_socket(intr, SC_SOCKET_NONE);
    return w;
}