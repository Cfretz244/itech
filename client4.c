/* Copyright (c) 2015 Rutgers University and Richard P. Martin.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without written agreement is
 * hereby granted, provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 *    3. Neither the name of the University nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 * IN NO EVENT SHALL RUTGERS UNIVERSITY BE LIABLE TO ANY PARTY FOR DIRECT,
 * INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT
 * OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF RUTGERS
 * UNIVERSITY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * RUTGERS UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND RUTGERS UNIVERSITY HAS NO OBLIGATION TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 *
 *
 * Author:                      Richard P. Martin
 * Version:                     1
 * Creation Date:				Tue Apr 28 16:55:25 EDT 2015
 * Filename:					client4.c
 */

/* this is the CS 352 spring 2015 client program for the bandwidth challenge test.
 * Students must complete the sock352 calls for this library for this client to work
 * with the corresponding server. See sock352.h for the definition
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <fcntl.h>
#include <time.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#include "sock352.h"

#define BUFFER_SIZE 32768

void usage() {
		printf("client4: usage: -s <size in MB> -i <seed> -d <destination> -n -u <udp-port> -l <local-port> -r <remote-port> \n");
}

/* timer function that returns the lapsed number of micro-seconds since epoch
 * (epoch is Jan 1, 1970 ) */
uint64_t lapsed_usec(struct timeval * start, struct timeval *end){
	uint64_t bt, be;  /* start, end times as 64 bit integers */

	bt =  (uint64_t) start->tv_sec *(1000000) + (uint64_t )start->tv_usec;
	be =  (uint64_t) end->tv_sec *(1000000) + (uint64_t ) end->tv_usec;
	/* make sure we don't return a negative time */
	if (be >= bt) {
		return (be-bt);
	}
	else {
		printf("client4: lapsed_usec: warning, negative time interval\n");
		return 0;
	}
} /* end lapsed_usec */

int generate_bytes(uint8_t *buffer, int buffer_size) {
	uint32_t i,e,s ;
	uint32_t *base_addr;
	uint32_t initval;

	if  (  (buffer_size % (sizeof(unsigned int))) != 0 ) {
		printf ("transmit buffer must be a multiple of the word size %d", (int) sizeof(int));
		exit(-1);
	}
	if (buffer_size == 0){
		printf ("transmit buffer size must be >0 ");
		exit(-1);
	}
	base_addr = (uint32_t *)buffer;
	initval = lrand48();

	e = buffer_size / sizeof(int) ;
	base_addr[0]= initval;

	for (i =1; i < e; i++) {
		s = i % 32;
		buffer[i] = ( initval << s)  | (initval >> 32-s);
	}
	return buffer_size;
}
int main(int argc, char *argv[]) {
	int input_size_mb;  /* size of the buffer to send to the server in megabytes */
	int input_size_bytes;  /* size of the buffer in bytes*/
	uint32_t buffer_size;    /* size of the file, in bytes */
	uint32_t input_size_network;  /* size of the file in network byte order */
	uint32_t init_seed;        /* seed for the random number generator */

	char *destination;    /* name of the server, or server's IP address */
	sockaddr_sock352_t dest_addr;  /* destination address as a CS 352 socket address */
	int dest_sock;        /* destination socket address */
	uint32_t cs352_port;  /* CS 352 port space port */
	uint32_t udp_port;    /* UDP to run the CS 352 sockets over */
	uint32_t local_port; /* UDP port to use as the local listen  address */
	uint32_t remote_port;   /* UDP port to use as the remote destination address */
	struct hostent *hp;   /* the host pointer for resolving names */

	char buffer[BUFFER_SIZE]; /* read/write buffer */
	int end_of_file, total_bytes, bytes_read;
	int bw;                   /* bytes written */
	struct timeval begin_time, end_time; /* start, end time to compute bandwidth */
	uint64_t lapsed_useconds;   /* micro-seconds since epoch */
	double lapsed_seconds;      /* difference from start and stop of the timer */
	MD5_CTX md5_context;     	/*   supports computing the file checksum */
	int compute_checksum;       /* compute the checksum or not */
	unsigned char md5_out[MD5_DIGEST_LENGTH];

	int retval;  /* return code for library operations */
	int c,i; /* index pointers */

	input_size_mb = 0;
	init_seed = 0xDEADBEEF;

	destination = NULL;
	/* set defaults */
	udp_port = SOCK352_DEFAULT_UDP_PORT;
	local_port = remote_port = 0;
	compute_checksum = 1;

	/* Parse the arguments to get the input file name, port, and destination  */
	opterr = 0;
	while ((c = getopt (argc, argv, "i:s:d:u:l:r:n")) != -1) {
		switch (c) {
		case 'i':
			init_seed = atoi(optarg);
			break;
	      case 's':
	        input_size_mb = atoi(optarg);
	        break;
	      case 'c':
	        cs352_port = atoi(optarg);
	        break;
	      case 'u':
	        udp_port = atoi(optarg);
	        break;
	      case 'd':
	    	  destination = optarg;
	    	  break;
	      case 'l':
	    	  local_port =  atoi(optarg);
	    	  break;
	      case 'r':
	    	  remote_port =  atoi(optarg);
	    	  break;
	      case 'n':
	    	  compute_checksum =0;
	    	  break;
	      case '?':
	    	  usage();
	    	  exit(-1);
	    	  break;
	      default:
	        printf("client4: unknown option: ");
	        usage();
	        exit(-1);
	        break;
		}
	}

	/* open the local file */
	/* check the file exists */
	if (input_size_mb == 0) {
		printf("client4: no  buffer size specified: ");
		usage();
		exit(-1);
	}

	srand48(init_seed);

	input_size_bytes = input_size_mb * (1024*1024);


	/* check that we have a server */
	if (destination == NULL) {
		printf("client4: no remote host specified\n");
		usage();
		exit(-1);
	}

	/* the destination port overrides the UDP port setting */
	if (remote_port != 0) {
		udp_port = remote_port;
	}

	/* set the destination address */
	  dest_addr.sin_family = AF_CS352;
	  dest_addr.sin_port = htons(udp_port);
	  /* If an internet "a.d.c.d" address is specified, use inet_addr()
	   * to convert it into real address.  If host name is specified,
	   * use gethostbyname() to resolve its address */
	  dest_addr.sin_addr.s_addr = inet_addr(destination); /* if a decimal "a.b.c.d" format */
	  if (dest_addr.sin_addr.s_addr == -1) {
	    hp = gethostbyname(destination);    /* if DNS name, e.g. x.y.com */
	    if (hp == NULL) {
	      printf("client4: host name %s not found\n", destination);
	      exit(-1);
	    }
	    memcpy(&(dest_addr.sin_addr),hp->h_addr, hp->h_length);
	  }

    /* change which init function to use based on the arguments */
	/* if BOTH the local and remote ports are set, use the init2 function */
	if ( (remote_port > 0) && (local_port > 0) ) {
		retval =  sock352_init2(remote_port, local_port);
	} else {
		retval = sock352_init(udp_port);
	}
	if (retval == SOCK352_FAILURE) {
			fprintf(stderr,"client4: initialization of 352 sockets on UDP port %d failed\n",udp_port);
			exit(-1);
	}
	  /* Create a CS 352 stream socket */
	if ( (dest_sock = sock352_socket(AF_CS352, SOCK_STREAM, 0)) == -1 ) {
		printf("client4: sock called failed \n");
		exit(-1);
	}

	/* begin the sending process*/
	if (compute_checksum) MD5_Init(&md5_context);
	gettimeofday(&begin_time, (struct timezone *) NULL); /* get a start time stamp */

	if ( sock352_connect(dest_sock, &dest_addr, sizeof(dest_addr)) != SOCK352_SUCCESS) {
		printf("client4: connect failed");
		exit(-1);
	}

	/* the client first sends the size of the file, then the file */
	/* first send the size of the file as a 32 bit integer in network byte order */
	input_size_network = htonl(input_size_bytes);
	bw = sock352_write(dest_sock,&input_size_network,sizeof(input_size_network));
	if (bw != sizeof(input_size_network)) {
		printf("client4: write of file size failed \n");
		exit(-1);
	}
	/* now send the file proper */
	total_bytes = end_of_file = 0;
	while ( (total_bytes < input_size_bytes) &&   /* the main loop checks both if we've sent the whole file*/
			(! end_of_file) ) {            /* or there is some other error */

		bytes_read = generate_bytes(buffer,BUFFER_SIZE);  /* generate random buffer */
		if (bytes_read > 0) {                      /* check we sent something */
			total_bytes += bytes_read ;
			if ( (bw = sock352_write(dest_sock,buffer,bytes_read)) != bytes_read) {
				printf("client4: error writing byte at count %d bytes written %d \n",total_bytes,bw);
			} else {
				if (compute_checksum) MD5_Update(&md5_context, buffer, bytes_read);  /* update the checksum */
			}
		} else {
			end_of_file =1;   /* we got either zero bytes or and error, so finish the loop */
		}
	}
	if ( sock352_close(dest_sock) != SOCK352_SUCCESS) {
		printf("client4: error with socket close \n");
	}
	gettimeofday(&end_time, (struct timezone *) NULL); /* end time-stamp */
	if (compute_checksum) MD5_Final(md5_out, &md5_context);

	lapsed_useconds = lapsed_usec(&begin_time, &end_time);
	lapsed_seconds = (double) lapsed_useconds / (double) 1000000;
	printf("client4: sent %d bytes in %lf sec, bandwidth %8.4lf Mb/s \n", total_bytes,lapsed_seconds,
				( ( (double) total_bytes* 8) / ((double) lapsed_seconds) / ((double) (1024*1024) )));
	if (compute_checksum) {
		printf("client4: MD5-checksum: ");
		for(i=0; i < MD5_DIGEST_LENGTH; i++)
			printf("%02x", md5_out[i]);
		printf("\n");
	}

return 0;

}
