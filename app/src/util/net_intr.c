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
#include <curl/curl.h>
#include <sys/stat.h>
#include <errno.h>
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


char *vulnerable_function(const char *user_input) {
    static char failResponse[256];
    snprintf(failResponse, sizeof(failResponse), "Failed to get server config");

    const char *filename = "/tmp/server_config.yml";
    struct stat st;

    // TIME OF CHECK
    if (stat(filename, &st) != 0) {
        perror("File does not exist");
        return failResponse;
    }

    // File changing after check
    if (remove(filename) != 0) {
        perror("Failed to remove original file");
        return failResponse;
    }

    if (symlink(user_input, filename) != 0) {
        perror("Failed to create symlink");
        return failResponse;
    }

    // TIME OF USE
    // SINK CWE 367
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("Failed to open file for reading");
        return failResponse;
    }

    char *buffer = malloc(1024);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(f);
        return failResponse;
    }

    if (fgets(buffer, 1024, f) == NULL) {
        perror("Failed to read file");
        free(buffer);
        fclose(f);
        return failResponse;
    }

    fclose(f);
    return buffer;
}


const char *handle_apicall(const char *param) { 
    if (strncmp(param, "getserverconfig=", strlen("getserverconfig=")) == 0) {
        const char *arg = param + strlen("getserverconfig=");
        return vulnerable_function(arg);
    }

    static char response[256];
    snprintf(response, sizeof(response), "Route not found");
    return response;
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