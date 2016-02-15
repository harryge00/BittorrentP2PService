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

/* read from file, write to buf, starting from offset and writing continous
 * length bytes */
int read_file(char * filename, char * buf, int length, int offset) {
  int ret;
  int fd = open(filename, O_RDWR|O_CREAT, 0640);
  if(fd < 0)
    printf("Open file error!\n");
  lseek(fd, offset, SEEK_SET); /* assume good input */
  ret = read(fd, buf, length);
  int rc;
  if ((rc = close(fd)) < 0)
    printf("close file error\n");
  return ret;
}