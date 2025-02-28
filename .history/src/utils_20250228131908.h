#ifndef UTILS_H
#define UTILS_H

struct test_status_t
{
    int number_of_tries;
    int number_of_success;
    int number_of_tar_created;
};

void init_test_status(struct test_status_t *ts);
void print_test_status(struct test_status_t *ts);

void tar_init_header(tar_header *header);
void tar_print_header(tar_header *header);
unsigned int tar_compute_checksum(tar_header *entry);
void tar_generate(tar_header *header, char *content, size_t content_size, char *end_data, size_t end_size);
void tar_generate_empty(tar_header *header);
int run_extractor(char *path);

extern struct test_status_t test_status;
extern int update_checksum;

#endif
