#ifndef UTILS_H
#define UTILS_H
#include "constants.h"

struct test_status_t
{
    int number_of_tries;
    int number_of_success;
    int number_of_tar_created;

    int successful_with_negative_value;

    int name_fuzzing_success;
    int mode_fuzzing_success;
    int uid_fuzzing_success;
    int gid_fuzzing_success;
    int size_fuzzing_success;
    int mtime_fuzzing_success;
    int checksum_fuzzing_success;
    int typeflag_fuzzing_success;
    int linkname_fuzzing_success;
    int magic_fuzzing_success;
    int version_fuzzing_success;
    int uname_fuzzing_success;
    int gname_fuzzing_success;
    int end_of_file_fuzzing_success;
    int known_crash_fuzzing_success;
    int multi_file_fuzzing_success;
    int huge_content_fuzzing_success;
    int prefix_fuzzing_success;
    int padding_footer_fuzzing_success;
    int overflow_all_fuzzing_success;
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
