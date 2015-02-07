#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include "sock352.h"
#include "array.h"

/*---- Private Constants -----*/

#define MAX_UDP_PACKET 65536

/*----- Private Struct Declarations -----*/

typedef struct sock352_socket_t {
    int fd;
    sockaddr_sock352_t addr;
    socklen_t len;
} sock352_socket_t;

/*----- Helper Function Declarations -----*/

int send_packet(sock352_pkt_hdr_t *header, void *data, int nbytes, sock352_socket_t *socket);
int recv_packet(sock352_pkt_hdr_t *header, void *data, sock352_socket_t *socket);
struct sockaddr_in setup_sockaddr(sockaddr_sock352_t *addr);
void create_header(sock352_pkt_hdr_t header, uint8_t flags, uint16_t checksum, uint32_t len);
sock352_socket_t *create_352socket(int fd);

/*----- Globals -----*/

int uport = -1, fd_counter = 0;
int sequence_num = 0;

array *sockets;


int sock352_init(int udp_port) {
    if (udp_port <= 0) return SOCK352_FAILURE;

    uport = udp_port;
    sockets = create_array();
}

int sock352_socket(int domain, int type, int protocol) {
    if (domain != AF_CS352 || type != SOCK_STREAM || protocol != 0 || uport < 0) {
        return SOCK352_FAILURE;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int fd_352 = fd_counter++;
    if (fd < 0) return SOCK352_FAILURE;
    insert(sockets, fd_352, create_352socket(fd));

    return fd_352;
}

int sock352_bind(int fd, sockaddr_sock352_t *addr, socklen_t len) {
    sockaddr_sock352_t addr_copy;
    memcpy(addr, &addr_copy, sizeof(addr_copy));
    sock352_socket_t *socket = retrieve(sockets, fd);
    socket->addr = addr_copy;

    struct sockaddr_in udp_addr = setup_sockaddr(addr);
    return bind(socket->fd, (struct sockaddr *) &udp_addr, len);
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len) {
    sockaddr_sock352_t addr_copy;
    memcpy(addr, &addr_copy, sizeof(addr_copy));
    sock352_socket_t *socket = retrieve(sockets, fd);
    socket->addr = addr_copy;
    
    // Bind to local port.
    sockaddr_sock352_t laddr;
    laddr.sin_addr.s_addr = htonl(INADDR_ANY);
    laddr.sin_port = htons((short) uport);
    int bound = sock352_bind(fd, &laddr, len);
    if (!bound) return SOCK352_FAILURE;

    // Perform handshake.
    sock352_pkt_hdr_t header;
    create_header(header, SOCK352_SYN, 0, 0);
    send_packet(&header, NULL, 0, socket);
    sock352_pkt_hdr_t resp_header;
    if (recv_packet(&resp_header, NULL, 0, socket)) {

    }
}

int sock352_listen(int fd, int n) {
    // Would some day set up queue.
}

int sock352_accept(int _fd, sockaddr_sock352_t *addr, int *len) {

}

int send_packet(sock352_pkt_hdr_t *header, void *data, int nbytes, sock352_socket_t *socket) {
    struct sockaddr_in udp_addr = setup_sockaddr(&socket->addr);
    char packet[sizeof(sock352_pkt_hdr_t) + nbytes];
    memcpy(&packet, header, sizeof(sock352_pkt_hdr_t));
    if (data) memcpy(&packet + sizeof(sock352_pkt_hdr_t), data, nbytes);
    return sendto(socket->fd, packet, sizeof(packet), 0, (struct sockaddr *) &udp_addr, sizeof(udp_addr));
}

int recv_packet(sock352_pkt_hdr_t *header, void *data, sock352_socket_t *socket) {
    char response[MAX_UDP_PACKET];
    int recvd_bytes = 0, expected = sizeof(sock352_pkt_hdr_t);
    socklen_t addr_len = sizeof(sockaddr_sock352_t);

    // Setup timeout structure.
    struct timeval time;
    time.tv_sec = 0;
    time.tv_usec = 200000;

    // Receive header.
    while (recvd_bytes < expected) {
        fd_set to_read;
        FD_SET(socket->fd, &to_read);
        int status = select(socket->fd + 1, &to_read, NULL, NULL, &time);
        if (status < 0) return SOCK352_FAILURE;
        if (FD_ISSET(socket->fd, &to_read)) {
            char *ptr = response + recvd_bytes;
            int count = expected - recvd_bytes;
            int nbytes = recvfrom(socket->fd, ptr, count, 0, (struct sockaddr *) &socket->addr, &addr_len);
            recvd_bytes += nbytes;
        } else {
            break;
        }
    }
    if (recvd_bytes != expected) return 0;

    sock352_pkt_hdr_t tmp_header;
    memcpy(response, &tmp_header, sizeof(tmp_header));
    expected = tmp_header.payload_len;
    recvd_bytes = 0;

    while (recvd_bytes < expected) {
        fd_set to_read;
        FD_SET(socket->fd, &to_read);
        int status = select(socket->fd + 1, &to_read, NULL, NULL, &time);
        if (status < 0) return SOCK352_FAILURE;
        if (FD_ISSET(socket->fd, &to_read)) {
            char *ptr = response + recvd_bytes;
            int count = expected - recvd_bytes;
            int nbytes = recvfrom(socket->fd, ptr, count, 0, (struct sockaddr *) &socket->addr, &addr_len);
            recvd_bytes += nbytes;
        } else {
            break;
        }
    }
    if (recvd_bytes != expected) return 0;

    void *tmp_data = response;
    // TODO: Add checksum validation here.
    memcpy(tmp_data, data, expected);
    memcpy(&tmp_header, header, sizeof(tmp_header));

    return 1;
}

struct sockaddr_in setup_sockaddr(sockaddr_sock352_t *addr) {
    struct sockaddr_in udp_addr;
    memset(&udp_addr, 0, sizeof(udp_addr));
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr = addr->sin_addr;
    udp_addr.sin_port = addr->sin_port;
    return udp_addr;
}

void create_header(sock352_pkt_hdr_t header, uint8_t flags, uint16_t checksum, uint32_t len) {
    memset(&header, 0, sizeof(header));
    header.version = SOCK352_VER_1;
    header.flags = flags;
    header.header_len = sizeof(header);
    header.checksum = checksum;
    header.sequence_no = sequence_num;
    header.window = 1024;
    header.payload_len = len;
}

sock352_socket_t *create_352socket(int fd) {
    sock352_socket_t *socket = malloc(sizeof(sock352_socket_t));

    if (socket) {
        socket->fd = fd;
    }

    return socket;
}
