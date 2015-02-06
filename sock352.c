#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sock352.h"

/*----- Helper Function Declarations -----*/

struct sockaddr_in setup_sockaddr(sockaddr_sock352_t *addr);
sock352_pkt_hdr_t create_header(uint8_t flags, uint16_t checksum, uint32_t len);

int port_352 = -1, port_udp = -1;
int fd_352 = 0, fd_udp = 0;
int bound = 0, sequence_num = 0;


int sock352_init(int udp_port) {
    if (udp_port <= 0) return SOCK352_FAILURE;

    port_udp = udp_port;
}

int sock352_socket(int domain, int type, int protocol) {
    if (domain != AF_CS352 || type != SOCK_STREAM || protocol != 0 || port_udp < 0) {
        return SOCK352_FAILURE;
    }
    fd_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_udp < 0) return SOCK352_FAILURE;

    return fd_352;
}

int sock352_bind(int fd, sockaddr_sock352_t *addr, socklen_t len) {
    struct sockaddr_in udp_addr = setup_sockaddr(addr);
    bound = 1;
    return bind(fd_udp, (struct sockaddr *) &udp_addr, len);
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len) {
    struct sockaddr_in udp_addr = setup_sockaddr(addr);
    int bind_status = 0;

    // Bind to local port if not already bound.
    if (bound) {
        bind_status = 1;
    } else {
        sockaddr_sock352_t laddr;
        laddr.sin_addr.s_addr = htonl(INADDR_ANY);
        laddr.sin_port = htons((short) port_udp);
        bind_status = sock352_bind(fd, &laddr, len);
    }
    if (!bind_status) return SOCK352_FAILURE;

    // Setup timeout.
    struct timeval time;
    time.tv_sec = 0;
    time.tv_usec = 200000;
    if (setsockopt(fd_udp, SOL_SOCKET, SO_RCVTIMEO, &time, sizeof(time)) < 0) {
        return SOCK352_FAILURE;
    }

    // Perform handshake.
    sock352_pkt_hdr_t header = create_header(SOCK352_SYN, 0, 0);
    sendto(fd_udp, &header, sizeof(header), 0, (struct sockaddr *) &udp_addr, sizeof(udp_addr));
    char response[sizeof(header)];
    int length = sizeof(udp_addr);
    recvfrom(fd_udp, response, sizeof(header), 0, (struct sockaddr *) &udp_addr, &length);
}

int sock352_listen(int fd, int n) {
    // Would some day set up queue.
}

int sock352_accept(int _fd, sockaddr_sock352_t *addr, int *len) {

}

struct sockaddr_in setup_sockaddr(sockaddr_sock352_t *addr) {
    struct sockaddr_in udp_addr;
    memset(&udp_addr, 0, sizeof(udp_addr));
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr = addr->sin_addr;
    udp_addr.sin_port = addr->sin_port;
    return udp_addr;
}

sock352_pkt_hdr_t create_header(uint8_t flags, uint16_t checksum, uint32_t len) {
    sock352_pkt_hdr_t header;
    memset(&header, 0, sizeof(header));
    header.version = SOCK352_VER_1;
    header.flags = flags;
    header.header_len = sizeof(header);
    header.checksum = checksum;
    header.sequence_no = sequence_num;
    header.window = 1024;
    header.payload_len = len;
}
