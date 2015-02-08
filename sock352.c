#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include "sock352.h"
#include "array.h"

/*---- Private Constants -----*/

#define MAX_UDP_PACKET 65536

/*----- Private Struct Declarations -----*/

typedef enum sock352_types_t {
    SOCK352_UNSET,
    SOCK352_SERVER,
    SOCK352_CLIENT
} sock352_types_t;

typedef struct sock352_socket_t {
    int fd, sequence_num, bound;
    sock352_types_t type;
    sockaddr_sock352_t laddr, raddr;
    socklen_t len;
} sock352_socket_t;

/*----- Helper Function Declarations -----*/

int send_packet(sock352_pkt_hdr_t *header, void *data, int nbytes, sock352_socket_t *socket);
int recv_packet(sock352_pkt_hdr_t *header, void *data, sock352_socket_t *socket, int timeout, int save_addr);
void setup_sockaddr(sockaddr_sock352_t *addr, struct sockaddr_in *udp_addr);
int valid_packet(sock352_pkt_hdr_t *header, void *data, int flags, sock352_socket_t *socket, int check_sequence);
void create_header(sock352_pkt_hdr_t *header, int sequence_num, int ack_num, uint8_t flags, uint16_t checksum, uint32_t len);
void decode_header(sock352_pkt_hdr_t *header);
uint64_t htonll(uint64_t num);
uint64_t ntohll(uint64_t num);
int endian_check();
sock352_socket_t *create_352socket(int fd);

/*----- Globals -----*/

int uport = -1, fd_counter = 0, bound = 0;

array *sockets;

int sock352_init(int udp_port) {
    puts("Called init...");
    if (udp_port <= 0) return SOCK352_FAILURE;

    uport = udp_port;
    sockets = create_array();
}

int sock352_socket(int domain, int type, int protocol) {
    puts("Called socket...");
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
    puts("Called bind...");
    sock352_socket_t *socket = retrieve(sockets, fd);
    memcpy(&socket->laddr, addr, sizeof(sockaddr_sock352_t));

    struct sockaddr_in udp_addr;
    setup_sockaddr(addr, &udp_addr);
    return bind(socket->fd, (struct sockaddr *) &udp_addr, len);
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len) {
    puts("Called connect...");
    int e_count = 0;
    sock352_socket_t *socket = retrieve(sockets, fd);
    memcpy(&socket->raddr, addr, sizeof(sockaddr_sock352_t));
    socket->type = SOCK352_CLIENT;

    // Bind to local port.
    puts("Binding to local port...");
    sockaddr_sock352_t laddr;
    laddr.sin_addr.s_addr = htonl(INADDR_ANY);
    laddr.sin_port = htons((short) uport);
    int status = sock352_bind(fd, &laddr, len);
    if (status) return SOCK352_FAILURE;

    // Send SYN.
    puts("Sending SYN packet...");
    sock352_pkt_hdr_t header;
    create_header(&header, socket->sequence_num, 0, SOCK352_SYN, 0, 0);
    status = send_packet(&header, NULL, 0, socket);
    if (status < 0) return SOCK352_FAILURE;

    // Receive SYN/ACK.
    sock352_pkt_hdr_t resp_header;
    memset(&resp_header, 0, sizeof(resp_header));
    puts("Receiving SYN/ACK, cross your fingers...");
    status = recv_packet(&resp_header, NULL, socket, 1, 0);
    decode_header(&resp_header);
    while (!valid_packet(&resp_header, NULL, SOCK352_SYN | SOCK352_ACK, socket, 1) || status == SOCK352_FAILURE) {
        if (++e_count > 5) return SOCK352_FAILURE;
        printf("Receive failure #%d...\n", e_count);
        send_packet(&header, NULL, 0, socket);
        recv_packet(&resp_header, NULL, socket, 1, 0);
        decode_header(&resp_header);
    }
    puts("Successfully received SYN/ACK!");
    e_count = 0;
    socket->sequence_num++;

    // Send ACK.
    puts("Sending ACK...");
    create_header(&header, socket->sequence_num, resp_header.sequence_no + 1, SOCK352_ACK, 0, 0);
    send_packet(&header, NULL, 0, socket);

    // Make sure ACK was received.
    puts("Making sure ACK was received...");
    while (recv_packet(&resp_header, NULL, socket, 1, 0) != SOCK352_FAILURE) {
        if (++e_count > 5) return SOCK352_FAILURE;
        printf("ACK was not received. Try #%d...\n", e_count);
        create_header(&header, resp_header.sequence_no + 1, 0, SOCK352_ACK, 0, 0);
        send_packet(&header, NULL, 0, socket);
    }

    // Praise the gods!
    puts("CONNECTED!!!");
    return SOCK352_SUCCESS;
}

int sock352_listen(int fd, int n) {
    puts("Called listen...");

    sock352_socket_t *socket = retrieve(sockets, fd);
    socket->type = SOCK352_SERVER;

    return SOCK352_SUCCESS;
}

// FIXME: Need to fix the way this function handles addr.
int sock352_accept(int _fd, sockaddr_sock352_t *addr, int *len) {
    puts("Called accept");
    sock352_socket_t *socket = retrieve(sockets, _fd);

    while (1) {
        // Wait for SYN.
        int e_count = 0;
        puts("Waiting for initial SYN, fingers crossed...");
        sock352_pkt_hdr_t header;
        memset(&header, 0, sizeof(header));
        recv_packet(&header, NULL, socket, 0, 1);
        decode_header(&header);
        while (!valid_packet(&header, NULL, SOCK352_SYN, socket, 0)) {
            puts("Received packet was invalid, trying again");
            recv_packet(&header, NULL, socket, 0, 1);
            decode_header(&header);
        }
        puts("Received initial SYN!");

        // Send SYN/ACK.
        sock352_pkt_hdr_t resp_header;
        create_header(&resp_header, 0, header.sequence_no + 1, SOCK352_SYN | SOCK352_ACK, 0, 0);
        puts("Sending SYN/ACK...");
        send_packet(&resp_header, NULL, 0, socket);

        // Receive ACK.
        int valid = 1;
        puts("Waiting for ACK...");
        memset(&header, 0, sizeof(header));
        int status = recv_packet(&header, NULL, socket, 1, 0);
        decode_header(&header);
        while (!valid_packet(&header, NULL, SOCK352_ACK, socket, 1) || status == SOCK352_FAILURE) {
            if (++e_count > 5) {
                valid = 0;
                break;
            }
            printf("Receive failure #%d...\n", e_count);
            send_packet(&resp_header, NULL, 0, socket);
            status = recv_packet(&header, NULL, socket, 1, 0);
            decode_header(&header);
        }

        // Either return new socket for connection, or give up and start over.
        if (valid) {
            int fd = fd_counter++;
            insert(sockets, fd, create_352socket(fd));
            puts("CONNECTED!!!");
            return fd;
        }
    }
}

int sock352_read(int fd, void *buf, int count) {
    return 0;
}

int sock352_write(int fd, void *buf, int count) {
    return 0;
}

int sock352_close(int fd) {
    return 0;
}

int send_packet(sock352_pkt_hdr_t *header, void *data, int nbytes, sock352_socket_t *socket) {
    struct sockaddr_in udp_addr;
    setup_sockaddr(&socket->raddr, &udp_addr);
    char packet[sizeof(sock352_pkt_hdr_t) + nbytes];

    memcpy(&packet, header, sizeof(sock352_pkt_hdr_t));
    if (data) memcpy(&packet + sizeof(sock352_pkt_hdr_t), data, nbytes);
    int num_bytes = data ? sizeof(packet) : sizeof(sock352_pkt_hdr_t);

    return sendto(socket->fd, packet, num_bytes, 0, (struct sockaddr *) &udp_addr, sizeof(udp_addr));
}

// FIXME: This function is really broken currently. Need to define how I want to handle setting the initial
// remote address.
int recv_packet(sock352_pkt_hdr_t *header, void *data, sock352_socket_t *socket, int timeout, int save_addr) {
    char response[MAX_UDP_PACKET];
    int header_size = sizeof(sock352_pkt_hdr_t), status;
    struct sockaddr_in sender;
    socklen_t addr_len = sizeof(struct sockaddr_in);

    // Setup timeout structure.
    struct timeval time;
    time.tv_sec = 0;
    time.tv_usec = 200000;

    fd_set to_read;
    FD_SET(socket->fd, &to_read);
    if (timeout) {
        status = select(socket->fd + 1, &to_read, NULL, NULL, &time);
    } else {
        status = select(socket->fd + 1, &to_read, NULL, NULL, NULL);
    }
    if (status < 0) return SOCK352_FAILURE;
    if (FD_ISSET(socket->fd, &to_read)) {
        recvfrom(socket->fd, response, sizeof(response), 0, (struct sockaddr *) &sender, &addr_len);
    } else {
        return SOCK352_FAILURE;
    }
    if (save_addr) {
        socket->raddr.sin_port = sender.sin_port;
        socket->raddr.sin_addr = sender.sin_addr;
    }

    memcpy(header, response, sizeof(sock352_pkt_hdr_t));
    if (data) memcpy(data, response + header_size, header->payload_len);

    return SOCK352_SUCCESS;
}

int valid_packet(sock352_pkt_hdr_t *header, void *data, int flags, sock352_socket_t *socket, int check_sequence) {
    puts("Performing packet validation check");
    printf("Expected flags: %d\n", flags);
    printf("Received flags: %d\n", header->flags);
    int sequence_check;
    int flag_check = header->flags == flags;
    if (check_sequence) {
        printf("Expected sequence number: %d\n", socket->sequence_num + 1);
        printf("Received sequence number: %d\n", header->ack_no);
        sequence_check = header->ack_no == socket->sequence_num + 1;
    } else {
        sequence_check = 1;
    }
    // TODO: Add checksum validation here.
    printf("Overall validation result: %d\n", flag_check && sequence_check);
    return flag_check && sequence_check;
}

void setup_sockaddr(sockaddr_sock352_t *addr, struct sockaddr_in *udp_addr) {
    memset(udp_addr, 0, sizeof(struct sockaddr_in));
    udp_addr->sin_family = AF_INET;
    udp_addr->sin_addr = addr->sin_addr;
    udp_addr->sin_port = addr->sin_port;
}

void create_header(sock352_pkt_hdr_t *header, int sequence_num, int ack_num, uint8_t flags, uint16_t checksum, uint32_t len) {
    memset(header, 0, sizeof(header));
    header->version = SOCK352_VER_1;
    header->flags = flags;
    header->protocol = 0;
    header->header_len = htons(sizeof(header));
    header->checksum = htons(checksum);
    header->source_port = htonl(0);
    header->dest_port = htonl(0);
    header->sequence_no = htonll(sequence_num);
    header->ack_no = htonll(ack_num);
    header->window = htonl(1024);
    header->payload_len = htonl(len);
}

void decode_header(sock352_pkt_hdr_t *header) {
    header->header_len = ntohs(header->header_len);
    header->checksum = ntohs(header->checksum);
    header->source_port = ntohl(header->source_port);
    header->dest_port = ntohl(header->dest_port);
    header->sequence_no = ntohll(header->sequence_no);
    header->ack_no = ntohll(header->ack_no);
    header->window = ntohl(header->window);
    header->payload_len = ntohl(header->payload_len);
}

uint64_t htonll(uint64_t num) {
    if (endian_check()) {
        uint32_t *f_half = (uint32_t *) &num, tmp;
        uint32_t *s_half = f_half + 1;
        *f_half = htonl(*f_half);
        *s_half = htonl(*s_half);
        tmp = *f_half;
        memcpy(f_half, s_half, sizeof(uint32_t));
        memcpy(s_half, &tmp, sizeof(uint32_t));
    }
    return num;
}

uint64_t ntohll(uint64_t num) {
    return htonll(num);
}

int endian_check() {
    int num = 42;
    return *((char *) &num) == 42;
}

sock352_socket_t *create_352socket(int fd) {
    sock352_socket_t *socket = calloc(1, sizeof(sock352_socket_t));

    if (socket) {
        socket->fd = fd;
        socket->sequence_num = 0;
        socket->type = SOCK352_UNSET;
    }

    return socket;
}
