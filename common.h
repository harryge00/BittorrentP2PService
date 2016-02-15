#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include "sha.h"
#include "peer.h"
#define WHOHAS 0
#define IHAVE 1
#define GET 2
#define DATA 3
#define ACK 4
#define DENIED 5
#define SHA1_HASH_SIZE 20
#define MAX_LINE_LENGTH 255
#define OWNED 0
#define RECEIVING 1
#define NOT_STARTED 2
#define FILE_NAME_SIZE	255
#define BT_CHUNK_SIZE (512 * 1024)
#define MAX_DATA_PACKET_SIZE 1484


struct Request* parse_has_get_chunk_file(char* chunk_file, char* output_filename);
int all_chunk_finished();
char master_data_file_name[FILE_NAME_SIZE];