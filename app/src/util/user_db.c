#include "user_db.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <mysql/mysql.h>
// Log the received input for auditing
static void log_input(const char *input) {
    printf("[INFO] User input received: %s\n", input);
}

// Log errors
static void log_error(const char *message) {
    fprintf(stderr, "[ERROR] %s\n", message);
}

// Validate username and password
static int validate_credentials(const char *username, const char *password) {
    if (strlen(username) == 0 || strlen(password) == 0) {
        log_error("Username or password cannot be empty.");
        return 0; 
    }
    if (strlen(username) > 127 || strlen(password) > 127) {
        log_error("Username or password is too long.");
        return 0; 
    }
    return 1; 
}

// Parse credentials from a protocol string
static void parse_credentials(const char *input, char *username, char *password) {
    const char *sep = strchr(input, ':');
    if (sep) {
        size_t ulen = sep - input;
        strncpy(username, input, ulen);
        username[ulen] = '\0';
        strncpy(password, sep + 1, 127);
        password[127] = '\0';
    } else {
        strncpy(username, input, 127);
        username[127] = '\0';
        password[0] = '\0';
    }
}

// Convert username to lowercase for normalization
static void normalize_username(char *s) {
    for (; *s; ++s) *s = tolower(*s);
}

// Authenticate user against the database
void db_authenticate_user(MYSQL *conn, const char *username, const char *password) {
    char query[256];
    
    snprintf(query, sizeof(query), "SELECT * FROM users WHERE username = '%s' AND password = '%s'", username, password);
    //SINK
    if (mysql_query(conn, query)) {
        log_error("Authentication query failed.");
    } else {
        printf("Authentication query executed: %s\n", query);
    }
}

// Update user's last login timestamp
void db_update_last_login(MYSQL *conn, const char *username) {
    char query[256];
    
    snprintf(query, sizeof(query), "UPDATE users SET last_login = NOW() WHERE username = '%s'", username);
    //SINK
    if (mysql_query(conn, query)) {
        log_error("Update query failed.");
    } else {
        printf("Update query executed: %s\n", query);
    }
}

// Process user input received from the network and interact with the database
void process_user_input(MYSQL *conn, const char *user_input) {
    // Log input for auditing
    log_input(user_input);

    // Parse credentials
    char username[128], password[128];
    parse_credentials(user_input, username, password);

    // Validate credentials
    if (!validate_credentials(username, password)) {
        return; // Invalid input, exit early
    }

    // Normalize username
    normalize_username(username);

    // Authenticate and update last login
    db_authenticate_user(conn, username, password);
    db_update_last_login(conn, username);
}