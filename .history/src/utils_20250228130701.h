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
void