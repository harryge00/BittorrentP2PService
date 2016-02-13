#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"
#include "common.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"

void peer_run(bt_config_t *config);

int main(int argc, char **argv) {
  bt_config_t config;

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

void fill_header(char** packet_header, unsigned char packet_type, 
	unsigned short packet_length, unsigned int seq_number, unsigned int ack_number){
	 #define HEADER_LENGTH 16
  *packet_header = (char*)malloc(16);
  unsigned short magic_number = MAGIC_NUMBER;
  unsigned char version_number = VERSION_NUMBER;
  short header_length = HEADER_LENGTH;
  *(unsigned short*)(*packet_header) = htons(magic_number);
  *(unsigned char*)(*packet_header+2) = version_number;
  *(unsigned char*)(*packet_header+3) = packet_type;
  *(unsigned short*)(*packet_header+4) = htons(header_length);
  *(unsigned short*)(*packet_header+6) = htons(packet_length);
  *(unsigned int*)(*packet_header+8) = htonl(seq_number);
  *(unsigned int*)(*packet_header+12) = htonl(ack_number);
}

bt_config_t *tmp_config;

void process_get(char *chunkfile, char *outputfile) {
  printf("PROCESS GET SKELETON CODE CALLED.  Fill me in!  (%s, %s)\n", 
	chunkfile, outputfile);

  char sendBuf[BUFLEN];
  char **packet = &sendBuf;
  fill_header(packet, WHOHAS, 60, 0, 0);
  unsigned short packet_length = ntohs(*(unsigned short*)(sendBuf+6));
  spiffy_sendto(socket, buffer, packet_length, 0, dst_addr, sizeof(*dst_addr));
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
	
	tmp_config = config;

  int sock;
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
