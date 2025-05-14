#include "net_intr.h"
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>

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
    // Write user code to a file
    FILE *f = fopen("/tmp/injected.c", "w");
    fprintf(f, "#include <stdio.h>\nvoid injected() { %s }\n", input);
    fclose(f);

    // Compile the code as a shared library
    system("gcc -shared -fPIC -o /tmp/injected.so /tmp/injected.c");

    // Load the shared library
    void *handle = dlopen("/tmp/injected.so", RTLD_LAZY);
    if (!handle) {
        printf("dlopen failed: %s\n", dlerror());
        return;
    }

    // Get the injected function using dlsym
    //SINK
    void (*func)() = (void (*)())dlsym(handle, "injected");
    if (!func) {
        printf("dlsym failed: %s\n", dlerror());
        dlclose(handle);
        return;
    }

    // Call the injected function
    func();

    // Clean up
    dlclose(handle);
    unlink("/tmp/injected.c");
    unlink("/tmp/injected.so");
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
        }
    }

    sc_intr_set_socket(intr, SC_SOCKET_NONE);
    return r;
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
