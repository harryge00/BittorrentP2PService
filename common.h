#include <stdio.h>
#include <stdlib.h>
#include "sha.h"

#define WHOHAS 0
#define IHAVE 1
#define GET 2
#define DATA 3
#define ACK 4
#define DENIED 5
#define SHA1_HASH_SIZE 20
#define MAX_LINE_LENGTH 255
#define OWNED 0
#define NOT_STARTED 1
#define RECEIVING 2
#define DOWNLOADED 3
struct Chunk {
	int id;
	uint8_t hash[SHA1_HASH_SIZE];
	int state;	/* 0 owned, 1 receiving */
	char* data;
	int received_seq_number;
	int received_byte_number;
};

struct Request{
	char* chunk_file; //the file name of (GET chunk_file tarFile)
    int chunk_number;
    struct Chunk* chunks;
};


struct Request* parse_has_get_chunk_file(char* chunk_file, char* output_filename);