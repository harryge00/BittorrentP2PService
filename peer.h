#include "bt_parse.h"

int sock;
bt_config_t config;
struct Chunk {
	int id;
	uint8_t hash[SHA1_HASH_SIZE];
	int state;	/* 0 owned, 2 receiving */
	char* data;
	int received_seq_number;
	int received_byte_number;
};

struct Request{
	char* filename; //the file name of (GET chunk_file tarFile)
    int chunk_number;
    struct Chunk* chunks;
};
struct Request* current_request;
struct Request* has_chunk_table;
struct Request* total_chunk_table;
