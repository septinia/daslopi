#ifndef MY_RUST_FUNCTIONS_H
#define MY_RUST_FUNCTIONS_H

#include <stdint.h>

typedef struct {
    int cores;
    // Other fields...
} MineArgs;

struct Logger;

// Function to start logging and return a pointer to the Logger instance
struct Logger* start_logging(void);

const char* get_logs(struct Logger* logger_ptr);

// Function to clear logs
void clear_logs(struct Logger* logger_ptr);

void my_rust_function(const MineArgs *args, const char *url, const char *username , struct Logger* logger_ptr);

#endif // MY_RUST_FUNCTIONS_H