These files are for the Rutgers Computer Science Internet Technology 
(CS 352) class project. See the sakai site for more details. 

Please include the project partner's names here:

Person 1: 
Person 2: 

--------------------------------------------------------------------------

How to run client_crypto and server_crypto: 

  Case 1: you are running client/server across two different machines: Set the UDP port with the -u option and the destination with the -d option. Example:

      On state.cs.rutgers.edu:  ./server_crypto -u 8888 -k server-keys.txt
      On null.cs.rutgers.edu: ./client_crypto -f test_file.txt -o ./foo.txt -d state.cs.rutgers.edu -k client-keys.txt -u 8888

  Case 2: you are running client/server on the same machine. Set the the local and remote UDP ports with the -l and and -r options. Note that between the client and server, the local and remote ports would be swapped. That is, the local port for the client would be the remote port for the server, and visa-versa. Set the destination with the -d option to the loopback IP address. Example:

     On one machine, in one window: 
       ./server_crypto -l 8888 -r 9999 -k server-keys.txt

     In a different window, on the same machine as above:
       ./client_crypto -f test_file.txt -o ./foo.txt -d localhost -k client-keys.txt -l 9999 -r 8888

  To generate a key-pair for use by the sodium cryptography library: 
    ./server_crypto -p

If you want to find the souce code for the sodium libraries, follow this link: 

    http://download.libsodium.org/doc/
   
File list: 
   
   client.c: client for part 1
   server.c: server for part 1

   client2.c: client for part 2
   server2.c: server for part 2 

   client_crypto: client for part 3
   server_crypto: server for part 3

   client-keys.txt   public/private key file for the client_crypto program 
   server-keys.txt:  public/private key file for the server_crypto program 
 
   Makefile: used to build the client and server code. 

   sock352.h: definitions of what the students must implement 

   libsodium.a : library archive for encryption library
   sodium/*.h: header files for the sodium library 

   uthash.h utlist.h utarray.h: C-language libraries to implement hash tables, linked lists and arrays. 

For TA's and professors only: 
sock352lib.h: Internal structure definitions for the socket library
sock352lib.c: An implementation of the socket library


