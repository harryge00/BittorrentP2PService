#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"
#include "chunk.h"
#include <stdbool.h>
#include "common.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"

struct source_chunk {
	struct sockaddr peer_addr;
	int sock;
	uint8_t hash[SHA1_HASH_SIZE];
	struct source_chunk* next;
	int state;
};

struct source_chunk* download_waiting_queue = NULL;
int upload_chunk_id;
bool uploading = false;
struct sockaddr upload_addr;
int upload_sock;
int sent_seq_number, sent_byte_number;

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
  char sendBuf[BUFLEN];
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
  int i, chunk_id;
  char chunk_count;
  struct sockaddr* dst_addr;
  uint8_t* hash;
  switch(packet_type) {
  	case WHOHAS:
  		printf("receive WHOHAS\n");
  		chunk_count = buf[16];
  		char matched_count = 0;
  		for(i=0;i<chunk_count;i++) {
	        hash = (uint8_t*)(buf+20 + i*SHA1_HASH_SIZE);
	        if(find_chunk(hash)>=0){
	          memcpy(sendBuf + 20 + matched_count * SHA1_HASH_SIZE, hash, SHA1_HASH_SIZE);
	          matched_count++;
	        }
	    }
	    if(matched_count > 0) {
	    	fill_header(sendBuf, IHAVE, 20 + SHA1_HASH_SIZE * matched_count, 0, 0);
	    	sendBuf[16] = matched_count;
	    	dst_addr = (struct sockaddr*)&from;
	    	spiffy_sendto(sock, sendBuf, 20 + SHA1_HASH_SIZE * matched_count, 0, dst_addr, sizeof(*dst_addr));
	    }
  		break;
  	case IHAVE:
  		printf("receive IHAVE\n");
  		chunk_count = buf[16];
  		for(i=0;i<chunk_count;i++) {
  			hash = (uint8_t*)(buf+20 + i*SHA1_HASH_SIZE);
  			if(download_waiting_queue == NULL) {
  				download_waiting_queue = (struct source_chunk*) malloc(sizeof(struct source_chunk));
  				memcpy(download_waiting_queue->hash, hash, SHA1_HASH_SIZE);
  				download_waiting_queue->next = NULL;
  				download_waiting_queue->sock = sock;
  				download_waiting_queue->peer_addr = *(struct sockaddr*)&from;
  				fill_header(sendBuf, GET, 36, 0, 0);
  				memcpy(sendBuf+16, hash, SHA1_HASH_SIZE);
  				chunk_id = get_chunk_id(hash, current_request);
  				current_request->chunks[chunk_id].state=RECEIVING;
  				dst_addr = (struct sockaddr*)&from;
	    		spiffy_sendto(sock, sendBuf, 36, 0, dst_addr, sizeof(*dst_addr));
  				download_waiting_queue->state = RECEIVING;
  			} else {
  				struct source_chunk* p_chunk = download_waiting_queue;
  				while(1) {
  					if(memcmp(hash, p_chunk->hash, SHA1_HASH_SIZE) == 0) {
  						printf("another peer also has %s\n", (char*)hash);
  						break;
  					}
  					if(p_chunk->next == NULL) {
  						p_chunk->next = (struct source_chunk*) malloc(sizeof(struct source_chunk));
  						p_chunk = p_chunk->next;
  						memcpy(p_chunk->hash, hash, SHA1_HASH_SIZE);
		  				p_chunk->next = NULL;
		  				p_chunk->sock = sock;
		  				p_chunk->state = NOT_STARTED;
		  				p_chunk->peer_addr = *(struct sockaddr*)&from;
  					} else {
  						p_chunk = p_chunk->next;
  					}
  				}
  			}
  		}
  		break;
  	case GET:
  		printf("receive GET\n");
  		memcpy(hash, buf+16, SHA1_HASH_SIZE);
  		upload_chunk_id = find_chunk(hash);
  		sent_seq_number = 0; 
  		sent_byte_number = 0;
  		upload_sock = sock;
  		upload_addr = *(struct sockaddr*) &from;
  		break;
  	case DATA:
  		printf("receive DATA\n");
  		struct source_chunk* p_chunk = download_waiting_queue;
		while(p_chunk != NULL) {
			if(p_chunk->state == RECEIVING) {
				hash = p_chunk->hash;
				break;
			}
			p_chunk = p_chunk->next;
		}
		chunk_id = get_chunk_id(hash, current_request);
  		save_data_packet(buf, chunk_id);
  		current_request->chunks[chunk_id].received_seq_number = seq_number;
  		fill_header(sendBuf, ACK, 16, 0, seq_number);
  		dst_addr = (struct sockaddr*) &from;
  		spiffy_sendto(sock, sendBuf, 16, 0, dst_addr, sizeof(*dst_addr));
  		if(save_chunk() > 0) {
  			p_chunk->state = OWNED;
  			p_chunk = p_chunk->next;
  			if(p_chunk == NULL) {
  				printf("finished downloading request\n");
  			} else {
  				p_chunk->state = RECEIVING;
  				memset(sendBuf, 0, 16);
  				fill_header(sendBuf, GET, 36, 0, 0);
  				memcpy(sendBuf+16, p_chunk->hash, SHA1_HASH_SIZE);
  				dst_addr = &p_chunk->peer_addr;
  				spiffy_sendto(sock, sendBuf, 16, 0, dst_addr, sizeof(*dst_addr));
  			}
  		}
  		break;
  	case ACK:
  		printf("receive ACK %d\n", ack_number);
  		break;
  	case DENIED:
  		printf("receive DENIED\n");
  		break;
  	default:
  		printf("Unexpected packet type!\n");

  }
}

void process_get(char *chunkfile, char *outputfile) {
  printf("PROCESS GET SKELETON CODE CALLED.  Fill me in!  (%s, %s)\n", 
	chunkfile, outputfile);

  if(current_request != NULL) {
  	printf("previous request:%s, %d", current_request->filename, current_request->chunk_number);
  }

  current_request = parse_has_get_chunk_file(chunkfile, outputfile);

  char *sendBuf = (char*) malloc(BUFLEN);

  unsigned short packet_length;

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
  packet_length = 20 + 20 * chunk_count;
  fill_header(sendBuf, WHOHAS, packet_length, 0, 0);
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
    	FILE *fp = fopen(outf, "w+");
		fclose(fp);
      	process_get(chunkf, outf);
    }
  }
}
void send_data_packet() {
	char* sendBuf = (char*) malloc(BUFLEN);
	int data_length;
	if(sent_byte_number + MAX_DATA_PACKET_SIZE > BT_CHUNK_SIZE) {
		data_length = sent_byte_number + MAX_DATA_PACKET_SIZE - BT_CHUNK_SIZE;
	} else {
		data_length = MAX_DATA_PACKET_SIZE;
	}
	fill_header(sendBuf, DATA, data_length + 16, sent_seq_number + 1, 0);
	read_file(has_chunk_table->filename, sendBuf, data_length, 
		upload_chunk_id * BT_CHUNK_SIZE + sent_byte_number);
	printf("sending data %d (%d)\n", sent_seq_number + 1, sent_byte_number);
	spiffy_sendto(upload_sock, sendBuf, data_length+16, 0, &upload_addr, sizeof(upload_addr));
	sent_seq_number++;
	sent_byte_number += data_length;
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
  printf("init OK\n");
  //parse_chunk_file(config->has_chunk_file);
  has_chunk_table = parse_has_get_chunk_file(config->has_chunk_file, NULL);
  total_chunk_table = parse_total_chunk_file(config->chunk_file, NULL);
  printf("Parsed Ok\n");

  char read_buffer[MAX_LINE_LENGTH];
  FILE* master_chunk_file = fopen(config->chunk_file, "r");
  fgets(read_buffer, MAX_LINE_LENGTH, master_chunk_file);
  fclose(master_chunk_file);
  memset(master_data_file_name, 0, FILE_NAME_SIZE);
  sscanf(read_buffer, "File:%s", master_data_file_name);
  printf("master_data_file_name: %s\n", master_data_file_name);

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
    if(uploading) {
    	send_data_packet();
    }
    if(all_chunk_finished(current_request)){
      printf("all chunk finished, GET request DONE\n");
      free(current_request->filename);
      free(current_request->chunks);      
      free(current_request);
      current_request = NULL;
    }
  }
}
