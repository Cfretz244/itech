#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <pthread.h>
#include "sock352.h"
#include "array.h"
#include "queue.h"

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
int valid_sequence(sock352_pkt_hdr_t *header, int expected);
int valid_ack(sock352_pkt_hdr_t *header, int expected, int exact);

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
    puts("Sock352_Init: Starting...");
    if (udp_port <= 0 || uport >= 0) return SOCK352_FAILURE;

    uport = udp_port;
    sockets = create_array();
}

int sock352_socket(int domain, int type, int protocol) {
    puts("Sock352_Socket: Starting...");
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
    puts("Sock352_Bind: Starting...");
    sock352_socket_t *socket = retrieve(sockets, fd);
    memcpy(&socket->laddr, addr, sizeof(sockaddr_sock352_t));

    struct sockaddr_in udp_addr;
    setup_sockaddr(addr, &udp_addr);
    return bind(socket->fd, (struct sockaddr *) &udp_addr, len);
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len) {
    puts("Sock352_Connect: Starting...");
    int e_count = 0;
    sock352_socket_t *socket = retrieve(sockets, fd);
    memcpy(&socket->raddr, addr, sizeof(sockaddr_sock352_t));
    socket->type = SOCK352_CLIENT;

    // Bind to local port.
    puts("Sock352_Connect: Binding to local port...");
    sockaddr_sock352_t laddr;
    laddr.sin_addr.s_addr = htonl(INADDR_ANY);
    laddr.sin_port = htons((short) uport);
    int status = sock352_bind(fd, &laddr, len);
    if (status) return SOCK352_FAILURE;

    // Send SYN.
    puts("Sock352_Connect: Sending SYN packet...");
    sock352_pkt_hdr_t header;
    create_header(&header, socket->lseq_num, 0, SOCK352_SYN, 0, 0);
    status = send_packet(&header, NULL, 0, socket);
    if (status < 0) return SOCK352_FAILURE;

    // Receive SYN/ACK.
    sock352_pkt_hdr_t resp_header;
    puts("Sock352_Connect: Receiving SYN/ACK, cross your fingers...");
    status = recv_packet(&resp_header, NULL, socket, 1, 0);
    while (!valid_packet(&resp_header, NULL, SOCK352_SYN | SOCK352_ACK, socket) ||
            !valid_ack(&resp_header, socket->lseq_num, 1) || status == SOCK352_FAILURE) {
        if (++e_count > 5) return SOCK352_FAILURE;
        printf("Sock352_Connect: Receive failure #%d...\n", e_count);
        send_packet(&header, NULL, 0, socket);
        recv_packet(&resp_header, NULL, socket, 1, 0);
    }
    puts("Sock352_Connect: Successfully received SYN/ACK!");
    e_count = 0;
    socket->last_ack = header.ack_no;
    socket->lseq_num++;
    socket->rseq_num = resp_header.sequence_no;

    // Send ACK.
    puts("Sock352_Connect: Sending ACK...");
    create_header(&header, socket->lseq_num, socket->rseq_num, SOCK352_ACK, 0, 0);
    do {
        status = send_packet(&header, NULL, 0, socket);
        if (++e_count > 5) return SOCK352_FAILURE;
    } while (status == SOCK352_FAILURE);
    e_count = 0;

    // Make sure ACK was received, and increment remote sequence number if so.
    puts("Sock352_Connect: Making sure ACK was received...");
    while (recv_packet(&resp_header, NULL, socket, 1, 0) != SOCK352_FAILURE) {
        if (++e_count > 5) return SOCK352_FAILURE;
        printf("Sock352_Connect: ACK was not received. Try #%d...\n", e_count);
        send_packet(&header, NULL, 0, socket);
    }
    socket->rseq_num++;

    // In general, my implementation of TCP does not increment sequence numbers when sending ACKs,
    // however, in this case, it significantly simplifies the writing logic if we can assume that
    // write will be called with a unique sequence number, and so here it is incremented.
    socket->lseq_num++;

    // Praise the gods!
    puts("Sock352_Connect: CONNECTED!!!");
    return SOCK352_SUCCESS;
}

int sock352_listen(int fd, int n) {
    puts("Sock352_Listen: Starting...");

    sock352_socket_t *socket = retrieve(sockets, fd);
    socket->type = SOCK352_SERVER;

    return SOCK352_SUCCESS;
}

int sock352_accept(int _fd, sockaddr_sock352_t *addr, int *len) {
    puts("Sock352_Accept: Starting...");
    sock352_socket_t *socket = retrieve(sockets, _fd);

    while (1) {
        // Wait for SYN.
        int e_count = 0, status = SOCK352_FAILURE;
        puts("Sock352_Accept: Waiting for initial SYN, fingers crossed...");
        sock352_pkt_hdr_t header;
        memset(&header, 0, sizeof(header));
        status = recv_packet(&header, NULL, socket, 0, 1);
        while (!valid_packet(&header, NULL, SOCK352_SYN, socket) || status == SOCK352_FAILURE) {
            puts("Sock352_Accept: Received packet was invalid, trying again");
            status = recv_packet(&header, NULL, socket, 0, 1);
        }
        puts("Sock352_Accept: Received initial SYN!");
        socket->rseq_num = header.sequence_no;

        // Send SYN/ACK.
        sock352_pkt_hdr_t resp_header;
        create_header(&resp_header, socket->lseq_num, socket->rseq_num, SOCK352_SYN | SOCK352_ACK, 0, 0);
        puts("Sock352_Accept: Sending SYN/ACK...");
        do {
            status = send_packet(&resp_header, NULL, 0, socket);
            if (++e_count > 5) break;
        } while(status == SOCK352_FAILURE);
        if (e_count > 5) continue;
        e_count = 0;

        // Receive ACK.
        int valid = 1;
        puts("Sock352_Accept: Waiting for ACK...");
        memset(&header, 0, sizeof(header));
        status = recv_packet(&header, NULL, socket, 1, 0);
        while (!valid_packet(&header, NULL, SOCK352_ACK, socket) ||
                !valid_ack(&header, socket->lseq_num, 1) || status == SOCK352_FAILURE) {
            if (++e_count > 5) {
                valid = 0;
                break;
            }
            printf("Sock352_Accept: Receive failure #%d...\n", e_count);
            send_packet(&resp_header, NULL, 0, socket);
            status = recv_packet(&header, NULL, socket, 1, 0);
        }
        socket->last_ack = header.ack_no;
        socket->lseq_num++;
        socket->rseq_num = header.sequence_no;

        // Either return new socket for connection, or give up and start over.
        if (valid) {
            int fd = fd_counter++;
            insert(sockets, fd, copysock(socket));
            puts("Sock352_Accept: CONNECTED!!!");
            return fd;
        }
    }
}

int sock352_read(int fd, void *buf, int count) {
    if (count <= 0 || !buf) {
        return 0;
    }
    puts("Sock352_Read: Starting...");

    sock352_socket_t *socket = retrieve(sockets, fd);
    int e_count = 0, status = 0, read = 0;
    char tmp_buf[MAX_UDP_PACKET * 2];
    sock352_pkt_hdr_t header, resp_header;

    // Check if there is buffered data that needs to be delivered to the calling process.
    if (socket->temp.size > 0) {
        puts("Sock352_Read: Found buffered data...");
        int to_move = 0;
        // Check if the provided memory is large enough to include everything in the buffer.
        // If not, calculate how much to copy.
        if (socket->temp.size > count) {
            to_move = count;
        } else if (socket->temp.size <= MAX_UDP_PACKET){
            to_move = socket->temp.size;
        } else {
            to_move = MAX_UDP_PACKET;
        }

        // Copy the calculated number of bytes from the buffer to the current packet storage.
        memcpy(tmp_buf, socket->temp.data, to_move);
        socket->temp.size -= to_move;

        // If we didn't empty the buffer, move all of the yet to be retrieved data to the front.
        if (socket->temp.size > 0) {
            uint32_t size = socket->temp.size;
            char *ptr = socket->temp.data;
            memcpy(ptr, ptr + to_move, size);
        }

        // Update the number of read bytes.
        read += to_move;
        printf("Sock352_Read: Moved %d bytes from the buffer into the current packet storage...\n", to_move);
    }

    // Receive and verify packet, updating the remote sequence number upon a pass.
    memset(&header, 0, sizeof(header));
    status = recv_packet(&header, tmp_buf + read, socket, 1, 0);
    puts("Sock352_Read: Received a packet, validating...");
    while (!valid_packet(&header, tmp_buf + read, 0, socket) ||
            !valid_sequence(&header, socket->rseq_num + 1) || status == SOCK352_FAILURE) {
        if (++e_count > 5) break;
        printf("Sock352_Read: Socket validation failure #%d...\n", e_count);

        // FIXME: Potential, but exceedingly unlikely, issue here. If we run into deadlock
        // conditions, re-evaluate checking the status of this send.
        create_header(&resp_header, socket->lseq_num, socket->rseq_num, SOCK352_ACK, 0, 0);
        send_packet(&resp_header, NULL, 0, socket);

        status = recv_packet(&header, tmp_buf + read, socket, 1, 0);
    }
    if (e_count > 5) return 0;
    socket->rseq_num = header.sequence_no;

    // If the packet reception was successful, send ACK, and return any buffered data, plus
    // whatever received data will fit in the given memory, otherwise just return any buffered
    // data.
    if (e_count < 5) {
        puts("Sock352_Read: Packet passed validation...");
        int to_move = 0, received = 1;
        // Data was successfully received, check if we need to/can buffer any of the received
        // data.
        if (read + header.payload_len <= count) {
            puts("Sock352_Read: No buffering is necessary, can return all data...");
            // No buffering is necessary. Return all received data.
            to_move = read + header.payload_len;
        } else {
            // Buffering is necessary. Check if we have enough space for it.
            to_move = count;
            uint32_t size = header.payload_len - count + read;
            if (size + socket->temp.size <= MAX_UDP_PACKET * 2) {
                // There is enough buffer space left for excess received data. Store it.
                puts("Sock352_Read: Buffering is necessary. Moving excess data into buffer...");
                char *data = socket->temp.data;
                memcpy(data + socket->temp.size, tmp_buf + count, size);
                socket->temp.size += size;
            } else {
                // There is not enough buffer space left for excess received data. Dump it and
                // set the received flag to zero so that an ACK will not be send for the
                // discarded data.
                puts("Sock352_Read: Buffering is necessary, but there isn't enough space. Discarding...");
                received = 0;
                to_move = read;
            }
        }

        // Send an ACK if the data was successfully/did not need to be buffered.
        if (received) {
            e_count = 0;
            printf("Sock352_Read: Sending ACK #%d...\n", socket->rseq_num);
            create_header(&resp_header, socket->lseq_num, socket->rseq_num, SOCK352_ACK, 0, 0);
            do {
                status = send_packet(&resp_header, NULL, 0, socket);
                if (++e_count > 5) break;
            } while (status == SOCK352_FAILURE);
        }

        // If there is data to return, return it.
        puts("Sock352_Read: Returning received data...");
        if (to_move) memcpy(buf, tmp_buf, to_move);
        return to_move;
    } else if (read > 0) {
        // Data was not successfully received, however, there is still buffered data to return.
        puts("Sock352_Read: Data was not successfully received, but there was buffered data to return...");
        memcpy(buf, tmp_buf, read);
        return read;
    } else {
        // Data was not successfully received, and there is nothing in the buffer.
        puts("Sock352_Read: No Data to return...");
        return 0;
    }
}

int sock352_write(int fd, void *buf, int count) {
    if (count <= 0 || !buf) {
        return 0;
    }
    puts("Sock352_Write: Starting...");

    sock352_socket_t *socket = retrieve(sockets, fd);
    if (!socket) return SOCK352_FAILURE;
    int total = count, sent = 0, locked;

    // Create the ACK receiving thread.
    pthread_t thread;
    pthread_create(&thread, NULL, handle_acks, socket);

    // Although most likely unnecessary the first time, we lock the ack_mutex to read the
    // last_ack and sequence number, ensuring we have the very most recent information.
    pthread_mutex_lock(socket->ack_mutex);
    locked = 1;
    while (sent < total || socket->last_ack != socket->lseq_num - 1) {
        printf("Sock352_Write: Sent: %d, Total: %d...\n", sent, total);
        if ((socket->lseq_num - socket->last_ack) >= MAX_WINDOW_SIZE || sent == total) {
            puts("Sock352_Write: Waiting for ACKs...");
            // Execution halts here in the case either:
            //  1. We have run out of window space, and are waiting on either a timeout or
            //     successful ACK to continue.
            //  2. We have finished sending data, but have not received all ACKs yet.
            //     Execution resumes when either we receive a new ACK or we time out.
            pthread_cond_wait(socket->signal, socket->ack_mutex);
            
            // Check if the ACK receiving thread has detected a lost packet, and if so, jump back
            // the specified number of packets and resend.
            if (socket->go_back) {
                printf("Sock352_Write: Going back %d\n", socket->go_back);

                // FIXME: The go-back multiplier is currently hard coded. This needs to be fixed.
                sent -= (socket->go_back * 8192);
                socket->go_back = 0;
                continue;
            }

            // If all data has already been sent, jump us back to the condition check to see
            // if we've received all of the ACKs yet.
            if (sent == total) continue;
        }
        pthread_mutex_unlock(socket->ack_mutex);
        locked = 0;

        pthread_mutex_lock(socket->write_mutex);

        // The code duplication here pains me, but I believe both checks are necessary.
        if (socket->go_back) {
            printf("Sock352_Write: Going back %d\n", socket->go_back);
            sent -= (socket->go_back * MAX_UDP_PACKET);
            socket->go_back = 0;
            pthread_mutex_unlock(socket->write_mutex);
            continue;
        }

        // Figure out which and how many bytes to send in this packet.
        int current = total - sent, e_count = 0, status = SOCK352_FAILURE;
        void *ptr = buf + sent;
        if (current > MAX_UDP_PACKET) current = MAX_UDP_PACKET;

        // Create the header and send the data.
        sock352_pkt_hdr_t header;
        create_header(&header, socket->lseq_num++, socket->rseq_num, 0, 0, current);
        do {
            printf("Sock352_Write: About to send %d bytes...\n", current);
            status = send_packet(&header, ptr, current, socket);
            if (++e_count > 5) {
                socket->should_halt = 1;
                pthread_join(thread, NULL);
                return sent;
            }
        } while (status == SOCK352_FAILURE);
        sent += current;
        pthread_mutex_unlock(socket->write_mutex);

        // Lock ack_mutex so that when the loop reintializes, it's guaranteed to read the
        // most recent information. Set local locked variable so we remember to unlock the mutex
        // if the loop does not reinitialize.
        pthread_mutex_lock(socket->ack_mutex);
        locked = 1;
    }

    // Unlock mutex if the loop left it locked.
    if (locked) {
        pthread_mutex_unlock(socket->ack_mutex);
        locked = 0;
    }

    // Halt the ACK receiving thread.
    puts("Sock352_Write: Data sent, ACKs received, joining with ACK thread...");
    socket->should_halt = 1;
    pthread_join(thread, NULL);
    puts("Sock352_Write: Joined...");
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
    int e_count = 0;
    puts("Handle_Acks: Starting...");

    // Continue looping until the data sending thread decides we're done.
    while (!socket->should_halt) {
        sock352_pkt_hdr_t header;
        int time_counter = 0, status = SOCK352_FAILURE;
        memset(&header, 0, sizeof(header));
        puts("Handle_Acks: Waiting on packet");
        while (time_counter < 20 && !socket->should_halt && status == SOCK352_FAILURE) {
            status = recv_packet(&header, NULL, socket, 10, 0);
            time_counter++;
        }
        if ((status == SOCK352_FAILURE || e_count > 5) && !socket->should_halt) {
            // The receive operation has timed out, which indicates we've lost a packet and come
            // to a halt. Figure out the number of packets we need to jump back, and unblock the
            // sending thread.
            e_count = 0;
            pthread_mutex_lock(socket->write_mutex);
            int difference = socket->lseq_num - socket->last_ack;
            printf("Handle_Acks: Packet receive timed out, going back %d...\n", difference);
            socket->lseq_num = socket->last_ack + 1;
            socket->go_back = difference - 1;
            pthread_cond_signal(socket->signal);
            pthread_mutex_unlock(socket->write_mutex);
        }
        if (valid_packet(&header, NULL, SOCK352_ACK, socket) &&
                valid_ack(&header, socket->last_ack + 1, 0) && !socket->should_halt) {
            // We've received a valid ACK packet. Update last_ack.
            e_count = 0;
            pthread_mutex_lock(socket->ack_mutex);
            socket->last_ack = header.ack_no;
            printf("Handle_Acks: Packet Receive succeeded, updated last_ack to %d...\n", socket->last_ack);
            pthread_cond_signal(socket->signal);
            pthread_mutex_unlock(socket->ack_mutex);
        } else {
            e_count++;
        }
    }

    // Clear this condition to allow for subsequent write calls.
    socket->should_halt = 0;

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
    if (data) memcpy(packet + sizeof(sock352_pkt_hdr_t), data, nbytes);
    int num_bytes = data ? sizeof(packet) : sizeof(sock352_pkt_hdr_t);

    return sendto(socket->fd, packet, num_bytes, 0, (struct sockaddr *) &udp_addr, sizeof(udp_addr));
}

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
    FD_ZERO(&to_read);
    FD_SET(socket->fd, &to_read);
    if (timeout) {
        if (timeout != 1) time.tv_usec = timeout * 1000;
        status = select(socket->fd + 1, &to_read, NULL, NULL, &time);
    } else {
        status = select(socket->fd + 1, &to_read, NULL, NULL, NULL);
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
    decode_header(header);
    if (data) memcpy(data, response + header_size, header->payload_len);

    return SOCK352_SUCCESS;
}

int valid_packet(sock352_pkt_hdr_t *header, void *data, int flags, sock352_socket_t *socket) {
    printf("Valid_Packet: Expected flags: %d...\n", flags);
    printf("Valid_Packet: Received flags: %d...\n", header->flags);
    int flag_check = header->flags == flags;

    // TODO: Add checksum validation here.
    int sum_check = 1;
    return flag_check && sum_check;
}

int valid_sequence(sock352_pkt_hdr_t *header, int expected) {
    printf("Valid_Sequence: Expected Sequence: %d...\n", expected);
    printf("Valid_Sequence: Received Sequence: %d...\n", header->sequence_no);
    return header->sequence_no == expected;
}

int valid_ack(sock352_pkt_hdr_t *header, int expected, int exact) {
    printf("Valid_Ack: Expected ACK: %d...\n", expected);
    printf("Valid_ack: Received ACK: %d...\n", header->ack_no);
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
