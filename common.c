#include "common.h"

struct Request* parse_has_get_chunk_file(char* chunk_file, char* output_filename){
  FILE *f;
  int chunk_count = 0;
  int i;
  uint8_t hash[SHA1_HASH_SIZE*2+1];
  uint8_t binary_hash[SHA1_HASH_SIZE];
  char line[MAX_LINE_LENGTH];
  struct Chunk* p_chunk;
  f = fopen(chunk_file, "r");
  if(f==NULL){
    return NULL;
  }
  while (fgets(line, MAX_LINE_LENGTH, f) != NULL) {
    if (line[0] == '#'){
      continue;
    }
    chunk_count++;
  }
  fseek(f, 0, SEEK_SET);
  struct Request* request = (struct Request*)malloc(sizeof(struct Request));
  request->filename = NULL;
  request->chunk_number = chunk_count;
  request->chunks = (struct Chunk*)malloc(sizeof(struct Chunk) * chunk_count);
  p_chunk = request->chunks;
  i = 0;
  //int tempnum;
  while(fgets(line, MAX_LINE_LENGTH, f)) {
    sscanf(line, "%d %s", &(p_chunk[i].id), hash);
    hex2binary((char*)hash, SHA1_HASH_SIZE*2, binary_hash);
    memcpy((char*)(p_chunk[i].hash), (char*)binary_hash, sizeof(binary_hash));
    if(output_filename!=NULL){
      p_chunk[i].state = NOT_STARTED;
    }
    else{
      p_chunk[i].state = OWNED; 
    }
    p_chunk[i].received_seq_number = 0;
    p_chunk[i].received_byte_number = 0;
    p_chunk[i].data = NULL;
    i++;
  }
  fclose(f);
  if(output_filename!=NULL){
    request->filename = (char*)malloc(FILE_NAME_SIZE);
    memcpy(request->filename, output_filename, FILE_NAME_SIZE);
  }
  return request;
}

struct Request* parse_total_chunk_file(char* chunk_file, char* output_filename){
  FILE *f;
  int chunk_count = 0;
  int i;
  uint8_t hash[SHA1_HASH_SIZE*2+1];
  uint8_t binary_hash[SHA1_HASH_SIZE];
  char line[MAX_LINE_LENGTH];
  struct Chunk* p_chunk;
  f = fopen(chunk_file, "r");
  if(f==NULL){
    return NULL;
  }
  fgets(line, MAX_LINE_LENGTH, f);
  fgets(line, MAX_LINE_LENGTH, f);
  while (fgets(line, MAX_LINE_LENGTH, f) != NULL) {
    if (line[0] == '#'){
      continue;
    }
    chunk_count++;
  }
  fseek(f, 0, SEEK_SET);
  struct Request* request = (struct Request*)malloc(sizeof(struct Request));
  request->filename = NULL;
  request->chunk_number = chunk_count;
  request->chunks = (struct Chunk*)malloc(sizeof(struct Chunk) * chunk_count);
  p_chunk = request->chunks;
  i = 0;
  //int tempnum;
  fgets(line, MAX_LINE_LENGTH, f);
  fgets(line, MAX_LINE_LENGTH, f);
  while(fgets(line, MAX_LINE_LENGTH, f)) {
    sscanf(line, "%d %s", &(p_chunk[i].id), hash);
    hex2binary((char*)hash, SHA1_HASH_SIZE*2, binary_hash);
    memcpy((char*)(p_chunk[i].hash), (char*)binary_hash, sizeof(binary_hash));
    if(output_filename!=NULL){
      p_chunk[i].state = NOT_STARTED;
    }
    else{
      p_chunk[i].state = OWNED; 
    }
    p_chunk[i].received_seq_number = 0;
    p_chunk[i].received_byte_number = 0;
    p_chunk[i].data = NULL;
    i++;
  }
  fclose(f);
  if(output_filename!=NULL){
    request->filename = (char*)malloc(FILE_NAME_SIZE);
    memcpy(request->filename, output_filename, FILE_NAME_SIZE);
  }
  return request;
}


/* open or create a file */
int open_file(char * filename) {
  int fd = open(filename, O_RDWR|O_CREAT, 0640);
  if(fd < 0)
    printf("Open file error!\n");
  return fd;
}

/* close the file */
void close_file(int fd) {
  int rc;
  if ((rc = close(fd)) < 0)
    printf("close file error\n");
}

/* create a file with fixed size, i.e. allocate a free space on storage */
int create_file(char * filename, int size) {
  int ret;
  int fd = open_file(filename);
  lseek(fd, size - 1, SEEK_SET); /* assume good input */
  ret = write(fd, "", 1);
  close_file(fd);
  return ret;
}

/* read from file, write to buf, starting from offset and writing continous
 * length bytes */
int read_file(char * filename, char * buf, int length, int offset) {
  int ret;
  int fd = open_file(filename);
  lseek(fd, offset, SEEK_SET); /* assume good input */
  ret = read(fd, buf, length);
  close_file(fd);
  return ret;
}



/* write buf to file, starting from offset and writing continous
 * length bytes */
int write_file(char * filename, char * buf, int length, int offset) {
  int ret;
  int fd = open_file(filename);
  lseek(fd, offset, SEEK_SET); /* assume good input */
  ret = write(fd, buf, length);
  close_file(fd);
  return ret;
}



int get_chunk_id(uint8_t* hash, struct Request* request) {
  int i = 0;
  for(i = 0; i < request->chunk_number; i++){
    if (memcmp(hash, request->chunks[i].hash, SHA1_HASH_SIZE) == 0) {
      return i;
    }
  }
  return -1;
}



void print_request(struct Request* request){
  if(request==NULL){
    printf("NULL request\n");
    return;
  }
  printf("Filename: %s, chunk_number: %d\n", request->filename, request->chunk_number);
  print_chunks(request->chunks, request->chunk_number);
}

void print_chunks(struct Chunk* chunks, int chunk_number){
  int i=0;
  char hash_buffer[SHA1_HASH_SIZE * 2 + 1];
  for (i = 0; i < chunk_number; ++i)
  {
    memset(hash_buffer, 0, SHA1_HASH_SIZE * 2 + 1);
    binary2hex(chunks[i].hash, SHA1_HASH_SIZE, hash_buffer);
    printf("id: %d Hash: %s state: %d\n", chunks[i].id, hash_buffer, chunks[i].state);
  }
}

int all_chunk_finished(){
  if(current_request==NULL){
    return 0;
  }
  int i=0;
  for(i=0;i<current_request->chunk_number;i++){
    if(current_request->chunks[i].state!=OWNED){
      return 0;
    }
  }
  return 1;
}


int save_chunk(int chunk_id){
  char* filename = NULL;
  struct Chunk* chunk = &current_request->chunks[chunk_id];
  if(chunk->received_byte_number == BT_CHUNK_SIZE&&chunk->state!=OWNED){
    chunk -> state = OWNED;
    // verify chunk
    uint8_t hash[SHA1_HASH_SIZE];
    shahash((uint8_t*)chunk->data, BT_CHUNK_SIZE, hash);
    // if chunk verify failed
    if (memcmp(hash, chunk->hash, SHA1_HASH_SIZE) != 0){
      char hash_buffer[SHA1_HASH_SIZE * 2 + 1];
      memset(hash_buffer, 0, SHA1_HASH_SIZE * 2 + 1);
      binary2hex(hash, SHA1_HASH_SIZE, hash_buffer);
      printf("Hash: %s\n", hash_buffer);
      printf("Verification failed!\n");
      chunk -> state = NOT_STARTED;
    }
    else{
      int offset = chunk->id * BT_CHUNK_SIZE;
      filename = current_request->filename;
      printf("chunk->id: %d, offset: %d\n", chunk->id, offset);
      write_file(filename, chunk->data, BT_CHUNK_SIZE, offset);
      update_ihave_table(chunk);
      printf("after update_ihave_table\n");
      print_request(has_chunk_table);
    }
    free(chunk->data);
    chunk->data = NULL;
    chunk->received_seq_number = 0;
    chunk->received_byte_number = 0;
    return 1;
  }
  return -1;
}
// save data in the packet
void save_data_packet(char* recvBuf, int chunk_id){
  struct Chunk* chunk = &current_request->chunks[chunk_id];
  if(chunk==NULL){
    return;
  }
  if(chunk->state == OWNED){
    return;
  }
  unsigned int seq_number = ntohl(*(unsigned int*)(recvBuf+8));
  unsigned short header_length = ntohs(*(unsigned short*)(recvBuf+4));
  unsigned short packet_length = ntohs(*(unsigned short*)(recvBuf+6));
  int data_size = packet_length - header_length;
  if(data_size < 0){
    data_size = 0;
  }
  if(data_size > MAX_DATA_PACKET_SIZE){
    printf("oops, seq %d data size %d\n", seq_number, data_size);
    data_size = MAX_DATA_PACKET_SIZE;
  }
  if(chunk->data == NULL&&chunk->state==RECEIVING){
    chunk->data = malloc(sizeof(char) * BT_CHUNK_SIZE);
  }
  // if(chunk->received_byte_number!=chunk->seq_number){
  //   printf("write to offset: %d, data_size: %d\n", chunk->received_byte_number, data_size);
  // }
  chunk->received_seq_number = seq_number;
  memcpy(chunk->data + chunk->received_byte_number, recvBuf + header_length, data_size);
  chunk->received_byte_number = chunk->received_byte_number + data_size;
}

void update_ihave_table(struct Chunk* chunk){
  if(get_chunk_id(chunk->hash, has_chunk_table)!=-1){
    return;
  }
  has_chunk_table->chunk_number = has_chunk_table->chunk_number + 1;
  struct Chunk* temp = (struct Chunk*)malloc(sizeof(struct Chunk) * has_chunk_table->chunk_number);
  int i=0;
  for(i = 0; i < has_chunk_table->chunk_number-1; ++i){
    temp[i].id = has_chunk_table->chunks[i].id;
    temp[i].state = has_chunk_table->chunks[i].state;
    temp[i].received_seq_number = has_chunk_table->chunks[i].received_seq_number;
    temp[i].received_byte_number = has_chunk_table->chunks[i].received_byte_number;
    temp[i].data = has_chunk_table->chunks[i].data;
    memcpy(temp[i].hash, has_chunk_table->chunks[i].hash, SHA1_HASH_SIZE);
  }
  temp[has_chunk_table->chunk_number-1].id = get_chunk_id(chunk->hash, total_chunk_table);
  temp[has_chunk_table->chunk_number-1].state = OWNED;
  temp[has_chunk_table->chunk_number-1].received_seq_number = 0;
  temp[has_chunk_table->chunk_number-1].received_byte_number = 0;
  temp[has_chunk_table->chunk_number-1].data = NULL;
  memcpy(temp[has_chunk_table->chunk_number-1].hash, chunk->hash, SHA1_HASH_SIZE);
  free(has_chunk_table->chunks);
  has_chunk_table->chunks = temp;
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

int find_chunk(uint8_t* hash){//if found, return the id of the chunk
  int i = 0;
  for(i = 0; i < has_chunk_table->chunk_number; i++){
    if (memcmp(hash, has_chunk_table->chunks[i].hash, SHA1_HASH_SIZE) == 0) {
      return has_chunk_table->chunks[i].id;
    }
  }
  return -1;
}