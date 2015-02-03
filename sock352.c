#include <stdlib.h>
#include <stdio.h>
#include "sock352.h"

/*----- Helper Function Declarations -----*/

void panic(char *reason);

int local_port = -1;
int current_fd = 0;
sockaddr_sock352_t *sock = NULL;

int sock352_init(int udp_port) {
    local_port = udp_port;
    sock = malloc(sizeof(sockaddr_sock352_t));
}

int sock352_socket(int domain, int type, int protocol) {
    if (domain != AF_INET || type != SOCK_STREAM || protocol != 0) {
        panic("Improper sock352_socket invocation");
    } else if (!sock) {
        panic("sock352_socket was called before initialization");
    }
}

void panic(char *reason) {
    fprintf(stderr, "ERROR: %s", reason);
    exit(EXIT_FAILURE);
}
