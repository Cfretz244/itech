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
    int fd, sequence_num;
    sockaddr_sock352_t addr;
    socklen_t len;
} sock352_socket_t;

/*----- Helper Function Declarations -----*/

int send_packet(sock352_pkt_hdr_t *header, void *data, int nbytes, sock352_socket_t *socket);
int recv_packet(sock352_pkt_hdr_t *header, void *data, sock352_socket_t *socket, int timeout);
struct sockaddr_in setup_sockaddr(sockaddr_sock352_t *addr);
int valid_packet(sock352_pkt_hdr_t *header, void *data, int flags, sock352_socket_t *socket, int check_sequence);
void create_header(sock352_pkt_hdr_t *header, int sequence_num, uint8_t flags, uint16_t checksum, uint32_t len);
sock352_socket_t *create_352socket(int fd);

/*----- Globals -----*/

int uport = -1, fd_counter = 0;

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
    int e_count = 0;
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

    // Send SYN.
    sock352_pkt_hdr_t header;
    create_header(&header, socket->sequence_num, SOCK352_SYN, 0, 0);
    send_packet(&header, NULL, 0, socket);

    // Receive SYN/ACK.
    sock352_pkt_hdr_t resp_header;
    int status = recv_packet(&resp_header, NULL, socket, 1);
    while (!valid_packet(&resp_header, NULL, SOCK352_SYN & SOCK352_ACK, socket, 1) || status == SOCK352_FAILURE) {
        if (++e_count > 5) return SOCK352_FAILURE;
        send_packet(&header, NULL, 0, socket);
        recv_packet(&resp_header, NULL, socket, 1);
    }
    e_count = 0;
    socket->sequence_num++;

    // Send ACK.
    create_header(&header, resp_header.sequence_no + 1, SOCK352_ACK, 0, 0);
    send_packet(&header, NULL, 0, socket);

    // Make sure ACK was received.
    while (recv_packet(&resp_header, NULL, socket, 1) != SOCK352_FAILURE) {
        if (++e_count > 5) return SOCK352_FAILURE;
        create_header(&header, resp_header.sequence_no + 1, SOCK352_ACK, 0, 0);
        send_packet(&header, NULL, 0, socket);
    }

    // Praise the gods!
    return SOCK352_SUCCESS;
}

int sock352_listen(int fd, int n) {
    // Would some day set up queue.
}

int sock352_accept(int _fd, sockaddr_sock352_t *addr, int *len) {
    int e_count = 0;
    sock352_socket_t *socket = retrieve(sockets, _fd);

    while (1) {
        // Wait for SYN.
        sock352_pkt_hdr_t header;
        recv_packet(&header, NULL, socket, 0);
        while (!valid_packet(&header, NULL, SOCK352_SYN, socket, 0)) {
            recv_packet(&header, NULL, socket, 1);
        }

        // Send SYN/ACK.
        sock352_pkt_hdr_t resp_header;
        create_header(&resp_header, header.sequence_no + 1, SOCK352_SYN & SOCK352_ACK, 0, 0);
        send_packet(&resp_header, NULL, 0, socket);

        // Receive ACK.
        int valid = 1;
        int status = recv_packet(&header, NULL, socket, 0);
        while (!valid_packet(&header, NULL, SOCK352_ACK, socket, 1) || status == SOCK352_FAILURE) {
            if (++e_count < 5) {
                valid = 0;
                break;
            }
            status = recv_packet(&header, NULL, socket, 1);
        }

        // Either return new socket for connection, or give up and start over.
        if (valid) {
            int fd = fd_counter++;
            insert(sockets, fd, create_352socket(fd));
            return fd;
        }
    }
}

int send_packet(sock352_pkt_hdr_t *header, void *data, int nbytes, sock352_socket_t *socket) {
    struct sockaddr_in udp_addr = setup_sockaddr(&socket->addr);
    char packet[sizeof(sock352_pkt_hdr_t) + nbytes];
    memcpy(&packet, header, sizeof(sock352_pkt_hdr_t));
    if (data) memcpy(&packet + sizeof(sock352_pkt_hdr_t), data, nbytes);
    return sendto(socket->fd, packet, sizeof(packet), 0, (struct sockaddr *) &udp_addr, sizeof(udp_addr));
}

int recv_packet(sock352_pkt_hdr_t *header, void *data, sock352_socket_t *socket, int timeout) {
    char response[MAX_UDP_PACKET];
    int recvd_bytes = 0, expected = sizeof(sock352_pkt_hdr_t);
    socklen_t addr_len = sizeof(sockaddr_sock352_t);

    // Setup timeout structure.
    struct timeval time;
    time.tv_sec = 0;
    time.tv_usec = 200000;

    // Receive header.
    while (recvd_bytes < expected) {
        int status;
        fd_set to_read;
        FD_SET(socket->fd, &to_read);
        if (timeout) {
            status = select(socket->fd + 1, &to_read, NULL, NULL, &time);
        } else {
            status = select(socket->fd + 1, &to_read, NULL, NULL, NULL);
        }
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
    if (recvd_bytes != expected) return SOCK352_FAILURE;

    sock352_pkt_hdr_t tmp_header;
    memcpy(response, &tmp_header, sizeof(tmp_header));
    expected = tmp_header.payload_len;
    recvd_bytes = 0;

    while (recvd_bytes < expected) {
        int status;
        fd_set to_read;
        FD_SET(socket->fd, &to_read);
        if (timeout) {
            status = select(socket->fd + 1, &to_read, NULL, NULL, &time);
        } else {
            status = select(socket->fd + 1, &to_read, NULL, NULL, NULL);
        }
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
    if (recvd_bytes != expected) return SOCK352_FAILURE;

    if (expected > 0) memcpy(response, data, expected);
    memcpy(&tmp_header, header, sizeof(tmp_header));

    return SOCK352_SUCCESS;
}

int valid_packet(sock352_pkt_hdr_t *header, void *data, int flags, sock352_socket_t *socket, int check_sequence) {
    int sequence_check;
    int flag_check = header->flags == flags;
    if (check_sequence) {
        sequence_check = header->ack_no == socket->sequence_num + 1;
    } else {
        sequence_check = 1;
    }
    // TODO: Add checksum validation here.
    return flag_check && sequence_check;
}

struct sockaddr_in setup_sockaddr(sockaddr_sock352_t *addr) {
    struct sockaddr_in udp_addr;
    memset(&udp_addr, 0, sizeof(udp_addr));
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr = addr->sin_addr;
    udp_addr.sin_port = addr->sin_port;
    return udp_addr;
}

void create_header(sock352_pkt_hdr_t *header, int sequence_num, uint8_t flags, uint16_t checksum, uint32_t len) {
    memset(header, 0, sizeof(header));
    header->version = SOCK352_VER_1;
    header->flags = flags;
    header->header_len = sizeof(header);
    header->checksum = checksum;
    header->sequence_no = sequence_num;
    header->window = 1024;
    header->payload_len = len;
}

sock352_socket_t *create_352socket(int fd) {
    sock352_socket_t *socket = malloc(sizeof(sock352_socket_t));

    if (socket) {
        socket->fd = fd;
        socket->sequence_num = 0;
    }

    return socket;
}
