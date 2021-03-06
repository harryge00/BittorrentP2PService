#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"
#include "chunk.h"

#include "common.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"
#define SHA1_HASH_SIZE 20

int sock;
bt_config_t config;

void peer_run(bt_config_t *config);

int main(int argc, char **argv) {

  bt_init(&config, argc, argv);

  DPRINTF(DEBUG_INIT, "peer.c main beginning\n");

#ifdef TESTING
  config.identity = 1; // your group number here
  strcpy(config.chunk_file, "chunkfile");
  strcpy(config.has_chunk_file, "haschunks");
#endif

  bt_parse_command_line(&config);

#ifdef DEBUG
  if (debug & DEBUG_INIT) {
    bt_dump_config(&config);
  }
#endif
  
  peer_run(&config);
  return 0;
}

void process_inbound_udp(int sock) {
  #define BUFLEN 1500
  struct sockaddr_in from;
  socklen_t fromlen;
  char buf[BUFLEN];

  fromlen = sizeof(from);
  spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen);
  //parsing recvBuf
  unsigned short magic_number = ntohs(*(unsigned short*)buf);
  unsigned char packet_version = *(unsigned char*)(buf+2);
  unsigned char packet_type = *(unsigned char*)(buf+3);
  unsigned short packet_header_len = ntohs(*(unsigned short*)(buf+4));
  unsigned short packet_len = ntohs(*(unsigned short*)(buf+6));
  unsigned int seq_number =ntohl(*(unsigned int*)(buf+8));
  unsigned int ack_number = ntohl(*(unsigned int*)(buf+12));

  printf("%d,%d,%d\n", magic_number, packet_version, packet_type);
  printf("%d,%d\n", packet_header_len, packet_len); 
  printf("PROCESS_INBOUND_UDP SKELETON -- replace!\n"
	 "Incoming message from %s:%d\n%s\n\n", 
	 inet_ntoa(from.sin_addr),
	 ntohs(from.sin_port),
	 buf);
  switch(packet_type) {
  	case WHOHAS:
  		printf("receive WHOHAS\n");
  		break;
  	case IHAVE:
  		printf("receive IHAVE\n");
  		break;
  	case GET:
  		printf("receive GET\n");
  		break;
  	case DATA:
  		printf("receive DATA\n");
  		break;
  	case ACK:
  		printf("receive ACK\n");
  		break;
  	case DENIED:
  		printf("receive DENIED\n");
  		break;
  	default:
  		printf("Unexpected packet type!\n");

  }
}

void fill_header(char* packet_header, unsigned char packet_type, 
	unsigned short packet_length, unsigned int seq_number, unsigned int ack_number){
	 #define HEADER_LENGTH 16
  unsigned short magic_number = 15441;
  unsigned char version_number = 1;
  short header_length = 16;
  *(unsigned short*)(packet_header) = htons(magic_number);
  *(unsigned char*)(packet_header+2) = version_number;
  *(unsigned char*)(packet_header+3) = packet_type;
  *(unsigned short*)(packet_header+4) = htons(header_length);
  *(unsigned short*)(packet_header+6) = htons(packet_length);
  *(unsigned int*)(packet_header+8) = htonl(seq_number);
  *(unsigned int*)(packet_header+12) = htonl(ack_number);
}

void process_get(char *chunkfile, char *outputfile) {
  printf("PROCESS GET SKELETON CODE CALLED.  Fill me in!  (%s, %s)\n", 
	chunkfile, outputfile);

  char *sendBuf = (char*) malloc(BUFLEN);

  unsigned short packet_length = ntohs(*(unsigned short*)(sendBuf+6));

  FILE *f = fopen(chunkfile, "r");
  char line[255];
  char chunk_count = 0;
  unsigned int id;
  uint8_t hash[SHA1_HASH_SIZE*2+1];
  uint8_t binary_hash[SHA1_HASH_SIZE];
  struct bt_peer_s* peer;
  struct sockaddr* dst_addr;
  // printf("len:%d, %s\n", packet_length, sendBuf);

  while (fgets(line, 255, f) != NULL) {
    if (line[0] == '#'){
      continue;
    }
    sscanf(line, "%d %s", &id, hash);
    hex2binary((char*)hash, SHA1_HASH_SIZE*2, binary_hash);
    memcpy(sendBuf + 20 + 20 * chunk_count, (char*)binary_hash, sizeof(binary_hash));
    chunk_count++;
    if(chunk_count >= 74 ) { //reached the maximum size of a packet
    	printf("WHOHAS packet has 74 chunks\n");
    	fill_header(sendBuf, WHOHAS, 1500, 0, 0);
    	*(sendBuf + 16) = chunk_count;
    	peer = config.peers;
	    while(peer!=NULL) {
	        if(peer->id==config.identity){
	          peer = peer->next;
	        }
	        else{
	          dst_addr = (struct sockaddr*)&peer->addr;
	          spiffy_sendto(sock, sendBuf, 1500, 0, dst_addr, sizeof(*dst_addr));
	          peer = peer->next;
	        }
	    }
	    memset(sendBuf, 0, BUFLEN);
    	chunk_count = 0;
    }
  }
  fclose(f);
  *(sendBuf + 16) = chunk_count;
  // printf("chunk_count:%d, %s\n", sendBuf[16], sendBuf);
  	peer = config.peers;
    while(peer!=NULL) {
        if(peer->id==config.identity){
          peer = peer->next;
        }
        else{
          dst_addr = (struct sockaddr*)&peer->addr;
          spiffy_sendto(sock, sendBuf, packet_length, 0, dst_addr, sizeof(*dst_addr));
          peer = peer->next;
        }
    }
    free(sendBuf);
}

void handle_user_input(char *line, void *cbdata) {
  char chunkf[128], outf[128];

  bzero(chunkf, sizeof(chunkf));
  bzero(outf, sizeof(outf));

  if (sscanf(line, "GET %120s %120s", chunkf, outf)) {
    printf("%s\n", line);
    if (strlen(outf) > 0) {
      process_get(chunkf, outf);
    }
  }
}


void peer_run(bt_config_t *config) {

  struct sockaddr_in myaddr;
  fd_set readfds;
  struct user_iobuf *userbuf;
  
  if ((userbuf = create_userbuf()) == NULL) {
    perror("peer_run could not allocate userbuf");
    exit(-1);
  }
  
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
    perror("peer_run could not create socket");
    exit(-1);
  }
  
  bzero(&myaddr, sizeof(myaddr));
  myaddr.sin_family = AF_INET;
  myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  myaddr.sin_port = htons(config->myport);
  
  if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
    perror("peer_run could not bind socket");
    exit(-1);
  }
  
  spiffy_init(config->identity, (struct sockaddr *)&myaddr, sizeof(myaddr));
  
  while (1) {
    int nfds;
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(sock, &readfds);
    
    nfds = select(sock+1, &readfds, NULL, NULL, NULL);
    
    if (nfds > 0) {
      if (FD_ISSET(sock, &readfds)) {
	process_inbound_udp(sock);
      }
      
      if (FD_ISSET(STDIN_FILENO, &readfds)) {
	process_user_input(STDIN_FILENO, userbuf, handle_user_input,
			   "Currently unused");
      }
    }
  }
}
