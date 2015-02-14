#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <pthread.h>
#include "sock352.h"
#include "array.h"
#include "list.h"

/*---- Private Constants -----*/

#define MAX_UDP_PACKET 65535
#define MAX_WINDOW_SIZE 1024
#define RECEIVE_TIMEOUT 200

/*----- Private Struct Declarations -----*/

typedef enum sock352_types {
    SOCK352_UNSET,
    SOCK352_SERVER,
    SOCK352_CLIENT
} sock352_types_t;

typedef struct storage {
    uint32_t size;
    void *data;
} storage_t;

typedef struct sock352_socket {
    int fd, bound, should_halt, go_back;
    uint64_t lseq_num, rseq_num, last_ack;
    sock352_types_t type;
    sockaddr_sock352_t laddr, raddr;
    storage_t temp;
    pthread_mutex_t *write_mutex, *ack_mutex;
    pthread_cond_t *signal;
    socklen_t len;
} sock352_socket_t;

/*----- Socket Manipulation Function Declarations -----*/

sock352_socket_t *create_352socket(int fd);
sock352_socket_t *copysock(sock352_socket_t *socket);
void *handle_acks(void *sock);
void destroy_352socket(sock352_socket_t *socket);

/*----- Packet Manipulation Function Declarations -----*/

int send_packet(sock352_pkt_hdr_t *header, void *data, int nbytes, sock352_socket_t *socket);
int recv_packet(sock352_pkt_hdr_t *header, void *data, sock352_socket_t *socket, int timeout, int save_addr);
int valid_packet(sock352_pkt_hdr_t *header, void *data, int flags, sock352_socket_t *socket);
int valid_sequence(sock352_pkt_hdr_t *header, int expected, int exact);

/*----- Header Manipulation Function Declarations -----*/

void create_header(sock352_pkt_hdr_t *header, int sequence_num, int ack_num, uint8_t flags, uint16_t checksum, uint32_t len);
void decode_header(sock352_pkt_hdr_t *header);
void setup_sockaddr(sockaddr_sock352_t *addr, struct sockaddr_in *udp_addr);

/*----- Misc. Utility Function Declarations -----*/

uint64_t htonll(uint64_t num);
uint64_t ntohll(uint64_t num);
int endian_check();

/*----- Globals -----*/

int uport = -1, fd_counter = 0;
array *sockets;

/*----- Socket API Function Implementations -----*/

int sock352_init(int udp_port) {
    puts("Called init...");
    if (udp_port <= 0 || uport >= 0) return SOCK352_FAILURE;

    uport = udp_port;
    sockets = create_array();
}

int sock352_socket(int domain, int type, int protocol) {
    puts("Called socket...");
    if (domain != AF_CS352 || type != SOCK_STREAM || protocol != 0) {
        return SOCK352_FAILURE;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return SOCK352_FAILURE;
    int fd_352 = fd_counter++;
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
    create_header(&header, socket->lseq_num, 0, SOCK352_SYN, 0, 0);
    status = send_packet(&header, NULL, 0, socket);
    if (status < 0) return SOCK352_FAILURE;

    // Receive SYN/ACK.
    sock352_pkt_hdr_t resp_header;
    puts("Receiving SYN/ACK, cross your fingers...");
    status = recv_packet(&resp_header, NULL, socket, RECEIVE_TIMEOUT, 0);
    decode_header(&resp_header);
    while (!valid_packet(&resp_header, NULL, SOCK352_SYN | SOCK352_ACK, socket) ||
            !valid_sequence(&resp_header, socket->lseq_num, 1) || status == SOCK352_FAILURE) {
        if (++e_count > 5) return SOCK352_FAILURE;
        printf("Receive failure #%d...\n", e_count);
        send_packet(&header, NULL, 0, socket);
        recv_packet(&resp_header, NULL, socket, RECEIVE_TIMEOUT, 0);
        decode_header(&resp_header);
    }
    puts("Successfully received SYN/ACK!");
    e_count = 0;
    socket->last_ack = header.ack_no;
    socket->lseq_num++;
    socket->rseq_num = resp_header.sequence_no;

    // Send ACK.
    puts("Sending ACK...");
    create_header(&header, socket->lseq_num, socket->rseq_num, SOCK352_ACK, 0, 0);
    do {
        status = send_packet(&header, NULL, 0, socket);
        if (++e_count > 5) return SOCK352_FAILURE;
    } while (status == SOCK352_FAILURE);
    e_count = 0;

    // Make sure ACK was received.
    puts("Making sure ACK was received...");
    while (recv_packet(&resp_header, NULL, socket, RECEIVE_TIMEOUT, 0) != SOCK352_FAILURE) {
        if (++e_count > 5) return SOCK352_FAILURE;
        printf("ACK was not received. Try #%d...\n", e_count);
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

int sock352_accept(int _fd, sockaddr_sock352_t *addr, int *len) {
    puts("Called accept");
    sock352_socket_t *socket = retrieve(sockets, _fd);

    while (1) {
        // Wait for SYN.
        int e_count = 0, status = SOCK352_FAILURE;
        puts("Waiting for initial SYN, fingers crossed...");
        sock352_pkt_hdr_t header;
        memset(&header, 0, sizeof(header));
        status = recv_packet(&header, NULL, socket, 0, 1);
        decode_header(&header);
        while (!valid_packet(&header, NULL, SOCK352_SYN, socket) || status == SOCK352_FAILURE) {
            puts("Received packet was invalid, trying again");
            status = recv_packet(&header, NULL, socket, 0, 1);
            decode_header(&header);
        }
        puts("Received initial SYN!");
        socket->rseq_num = header.sequence_no;

        // Send SYN/ACK.
        sock352_pkt_hdr_t resp_header;
        create_header(&resp_header, socket->lseq_num, socket->rseq_num, SOCK352_SYN | SOCK352_ACK, 0, 0);
        puts("Sending SYN/ACK...");
        do {
            status = send_packet(&resp_header, NULL, 0, socket);
            if (++e_count > 5) break;
        } while(status == SOCK352_FAILURE);
        if (e_count > 5) continue;
        e_count = 0;

        // Receive ACK.
        int valid = 1;
        puts("Waiting for ACK...");
        memset(&header, 0, sizeof(header));
        status = recv_packet(&header, NULL, socket, RECEIVE_TIMEOUT, 0);
        decode_header(&header);
        while (!valid_packet(&header, NULL, SOCK352_ACK, socket) ||
                !valid_sequence(&header, socket->lseq_num, 1) || status == SOCK352_FAILURE) {
            if (++e_count > 5) {
                valid = 0;
                break;
            }
            printf("Receive failure #%d...\n", e_count);
            send_packet(&resp_header, NULL, 0, socket);
            status = recv_packet(&header, NULL, socket, RECEIVE_TIMEOUT, 0);
            decode_header(&header);
        }
        socket->last_ack = header.ack_no;
        socket->lseq_num++;
        socket->rseq_num = header.sequence_no;

        // Either return new socket for connection, or give up and start over.
        if (valid) {
            int fd = fd_counter++;
            insert(sockets, fd, copysock(socket));
            puts("CONNECTED!!!");
            return fd;
        }
    }
}

// FIXME: Possible for function to eventually overflow temp storage.
int sock352_read(int fd, void *buf, int count) {
    if (count <= 0 || !buf) {
        return 0;
    }

    sock352_socket_t *socket = retrieve(sockets, fd);
    int e_count = 0, status = 0, read = 0;
    char tmp_buf[MAX_UDP_PACKET * 2];
    sock352_pkt_hdr_t header;

    if (socket->temp.size > 0) {
        int to_move = 0;
        if (socket->temp.size > count) {
            to_move = count;
        } else {
            to_move = socket->temp.size;
        }
        memcpy(tmp_buf, socket->temp.data, to_move);
        socket->temp.size -= to_move;
        if (socket->temp.size > 0) {
            uint32_t size = socket->temp.size;
            char *ptr = socket->temp.data;
            memcpy(ptr, ptr + to_move, size);
        }
        read += to_move;
    }

    status = recv_packet(&header, tmp_buf + read, socket, RECEIVE_TIMEOUT, 0);
    decode_header(&header);
    while (!valid_packet(&header, tmp_buf + read, 0, socket) ||
            !valid_sequence(&header, socket->rseq_num, 1) || status == SOCK352_FAILURE) {
        if (++e_count > 5) break;
        status = recv_packet(&header, tmp_buf + read, socket, RECEIVE_TIMEOUT, 0);
        decode_header(&header);
    }

    if (e_count < 5) {
        int to_move = 0;
        if (read + header.payload_len <= count) {
            to_move = read + header.payload_len;
        } else {
            to_move = count;
            uint32_t size = header.payload_len - count + read;
            char *data = socket->temp.data;
            memcpy(data + socket->temp.size, tmp_buf + count, size);
        }
        // Send ack.
        memcpy(buf, tmp_buf, to_move);
        return to_move;
    } else if (read > 0) {
        memcpy(buf, tmp_buf, read);
        return read;
    } else {
        return 0;
    }
}

int sock352_write(int fd, void *buf, int count) {
    if (count <= 0 || !buf) {
        return 0;
    }

    sock352_socket_t *socket = retrieve(sockets, fd);
    if (!socket) return SOCK352_FAILURE;
    int total = count, sent = 0;

    pthread_t thread;
    pthread_create(&thread, NULL, handle_acks, socket);

    while (sent < total) {
        pthread_mutex_lock(socket->ack_mutex);
        if ((socket->lseq_num - socket->last_ack) >= MAX_WINDOW_SIZE) {
            pthread_cond_wait(socket->signal, socket->ack_mutex);
        }
        pthread_mutex_unlock(socket->ack_mutex);

        pthread_mutex_lock(socket->write_mutex);
        if (socket->go_back) {
            sent -= (socket->go_back * MAX_UDP_PACKET);
            socket->go_back = 0;
            pthread_mutex_unlock(socket->write_mutex);
            continue;
        }

        int current = total - sent, e_count = 0, status = SOCK352_FAILURE;
        void *ptr = buf + sent;
        if (current > MAX_UDP_PACKET) current = MAX_UDP_PACKET;

        sock352_pkt_hdr_t header;
        create_header(&header, socket->lseq_num++, socket->rseq_num, 0, 0, current);
        do {
            status = send_packet(&header, ptr, current, socket);
            if (++e_count > 5) {
                socket->should_halt = 1;
                pthread_join(thread, NULL);
                return sent;
            }
        } while (status == SOCK352_FAILURE);
        sent += current;
        pthread_mutex_unlock(socket->write_mutex);
    }
    // FIXME: Need to actually check status of acks here.

    socket->should_halt = 1;
    pthread_join(thread, NULL);
    return sent;
}

int sock352_close(int fd) {
    return 0;
}

/*----- Socket Manipulation Function Implementations -----*/

sock352_socket_t *create_352socket(int fd) {
    sock352_socket_t *socket = calloc(1, sizeof(sock352_socket_t));

    if (socket) {
        socket->fd = fd;

        socket->temp.data = malloc(MAX_UDP_PACKET);

        socket->write_mutex = malloc(sizeof(pthread_mutex_t));
        pthread_mutex_init(socket->write_mutex, NULL);

        socket->ack_mutex = malloc(sizeof(pthread_mutex_t));
        pthread_mutex_init(socket->ack_mutex, NULL);

        socket->signal = malloc(sizeof(pthread_cond_t));
        pthread_cond_init(socket->signal, NULL);
    }

    return socket;
}

sock352_socket_t *copysock(sock352_socket_t *socket) {
    sock352_socket_t *copy = create_352socket(socket->fd);

    if (copy) {
        copy->bound = socket->bound;
        copy->lseq_num = socket->lseq_num;
        copy->rseq_num = socket->rseq_num;
        copy->last_ack = socket->last_ack;
        copy->type = socket->type;
        copy->laddr = socket->laddr;
        copy->raddr = socket->raddr;
        copy->len = socket->len;
    }

    return copy;
}

void *handle_acks(void *sock) {
    sock352_socket_t *socket = sock;

    while (!socket->should_halt) {
        sock352_pkt_hdr_t header;
        int status = recv_packet(&header, NULL, socket, RECEIVE_TIMEOUT, 0);
        if (status == SOCK352_FAILURE) {
            pthread_mutex_lock(socket->write_mutex);
            int difference = socket->lseq_num - socket->last_ack;
            socket->lseq_num = socket->last_ack + 1;
            socket->go_back = difference - 1;
            pthread_cond_signal(socket->signal);
            pthread_mutex_unlock(socket->write_mutex);
        }
        if (valid_packet(&header, NULL, SOCK352_ACK, socket) && valid_sequence(&header, socket->last_ack + 1, 0)) {
            socket->last_ack = header.ack_no;
        }
    }

    return NULL;
}

void destroy_352socket(sock352_socket_t *socket) {
    free(socket);
}

/*----- Packet Manipulation Function Implementations -----*/

int send_packet(sock352_pkt_hdr_t *header, void *data, int nbytes, sock352_socket_t *socket) {
    struct sockaddr_in udp_addr;
    setup_sockaddr(&socket->raddr, &udp_addr);
    char packet[sizeof(sock352_pkt_hdr_t) + nbytes];

    memcpy(&packet, header, sizeof(sock352_pkt_hdr_t));
    if (data) memcpy(&packet + sizeof(sock352_pkt_hdr_t), data, nbytes);
    int num_bytes = data ? sizeof(packet) : sizeof(sock352_pkt_hdr_t);

    return sendto(socket->fd, packet, num_bytes, 0, (struct sockaddr *) &udp_addr, sizeof(udp_addr));
}

int recv_packet(sock352_pkt_hdr_t *header, void *data, sock352_socket_t *socket, int timeout_msecs, int save_addr) {
    char response[MAX_UDP_PACKET];
    int header_size = sizeof(sock352_pkt_hdr_t), status;
    struct sockaddr_in sender;
    socklen_t addr_len = sizeof(struct sockaddr_in);

    // Setup timeout structure.
    struct timeval time;
    time.tv_sec = 0;
    time.tv_usec = timeout_msecs;

    fd_set to_read;
    FD_SET(socket->fd, &to_read);
    if (timeout_msecs) {
        select(socket->fd + 1, &to_read, NULL, NULL, &time);
    } else {
        select(socket->fd + 1, &to_read, NULL, NULL, NULL);
    }
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

int valid_packet(sock352_pkt_hdr_t *header, void *data, int flags, sock352_socket_t *socket) {
    puts("Performing packet validation check");
    printf("Expected flags: %d\n", flags);
    printf("Received flags: %d\n", header->flags);
    int flag_check = header->flags == flags;

    // TODO: Add checksum validation here.
    int sum_check = 1;
    printf("Overall validation result: %d\n", flag_check && sum_check);
    return flag_check && sum_check;
}

int valid_sequence(sock352_pkt_hdr_t *header, int expected, int exact) {
    if (exact) {
        return header->ack_no == expected;
    } else {
        return header->ack_no >= expected;
    }
}

/*----- Header Manipulation Function Implementations -----*/

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
    header->window = htonl(MAX_WINDOW_SIZE);
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

void setup_sockaddr(sockaddr_sock352_t *addr, struct sockaddr_in *udp_addr) {
    memset(udp_addr, 0, sizeof(struct sockaddr_in));
    udp_addr->sin_family = AF_INET;
    udp_addr->sin_addr = addr->sin_addr;
    udp_addr->sin_port = addr->sin_port;
}

/*----- Misc. Utility Function Implementations -----*/

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
