#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include "utils.h"

int update_checksum = 1;
struct test_status_t test_status;

void init_test_status(struct test_status_t *ts)
{
    memset(ts, 0, sizeof(struct test_status_t));
}

void print_test_status(struct test_status_t *ts)
{
    printf("/n/nTest Status Report\n");
    printf("Total tries: %d\n", ts->number_of_tries);
    printf("Total successes: %d\n", ts->number_of_success);
    printf("Tars created: %d\n\n", ts->number_of_tar_created);

    printf("Success on \n");
    printf("\t   name field       : %d\n", ts->name_fuzzing_success);
    printf("\t   mode field       : %d\n", ts->mode_fuzzing_success);
    printf("\t   uid field        : %d\n", ts->uid_fuzzing_success);
    printf("\t   gid field        : %d\n", ts->gid_fuzzing_success);
    printf("\t   size field       : %d\n", ts->size_fuzzing_success);
    printf("\t   mtime field      : %d\n", ts->mtime_fuzzing_success);
    printf("\t   checksum field   : %d\n", ts->checksum_fuzzing_success);
    printf("\t   typeflag field   : %d\n", ts->typeflag_fuzzing_success);
    printf("\t   linkname field   : %d\n", ts->linkname_fuzzing_success);
    printf("\t   magic field      : %d\n", ts->magic_fuzzing_success);
    printf("\t   version field    : %d\n", ts->version_fuzzing_success);
    printf("\t   uname field      : %d\n", ts->uname_fuzzing_success);
    printf("\t   gname field      : %d\n", ts->gname_fuzzing_success);
    printf("\t   known crash field: %d\n", ts->known_crash_fuzzing_success);
    printf("\t   multi file field : %d\n", ts->multi_file_fuzzing_success);
    printf("\t   huge content field: %d\n", ts->huge_content_fuzzing_success);
    printf("\t   prefix field     : %d\n", ts->prefix_fuzzing_success);
    printf("\t   padding field    : %d\n", ts->padding_footer_fuzzing_success);
    printf("\t   end of file field: %d\n\n", ts->end_of_file_fuzzing_success);
    printf("\t   overflow all field:%d\n\n", ts->overflow_all_fuzzing_success);
}

unsigned int tar_compute_checksum(tar_header *entry)
{
    memset(entry->chksum, ' ', sizeof(entry->chksum));
    unsigned int check = 0;
    unsigned char *raw = (unsigned char *)entry;
    for (int i = 0; i < HEADER_LENGTH; i++)
    {
        check += raw[i];
    }
    snprintf(entry->chksum, sizeof(entry->chksum), "%06o0", check);
    entry->chksum[6] = '\0';
    entry->chksum[7] = ' ';
    return check;
}

int run_extractor(char *path)
{
    test_status.number_of_tries++;
    char cmd[51];
    snprintf(cmd, sizeof(cmd), "%s archive.tar", path);
    char buf[128];
    FILE *fp = popen(cmd, "r");
    if (!fp)
    {
        printf("Error opening pipe for '%s': %s\n", path, strerror(errno)); // Debug
        return -1;
    }
    if (!fgets(buf, sizeof(buf), fp))
    {
        printf("Error reading from pipe: %s\n", strerror(errno)); // Debug
        pclose(fp);
        return 0;
    }
    int rv = strncmp(buf, "*** The program has crashed ***\n", 33) == 0;
    if (rv)
    {
        test_status.number_of_success++;
        char success_name[32];
        snprintf(success_name, sizeof(success_name), "success_%d.tar", test_status.number_of_success);
        rename("archive.tar", success_name);
        printf("Saved crash file: %s\n", success_name);
    }
    else
    {
        printf("Extractor output: '%s'\n", buf);
    }
    if (pclose(fp) == -1)
    {
        printf("Error closing pipe: %s\n", strerror(errno)); // Debug
    }
    return rv;
}

void tar_init_header(tar_header *header)
{
    memset(header, 0, sizeof(tar_header));
    snprintf(header->name, sizeof(header->name), "testfile");
    snprintf(header->mode, sizeof(header->mode), "0644");
    snprintf(header->uid, sizeof(header->uid), "01000");
    snprintf(header->gid, sizeof(header->gid), "01000");
    snprintf(header->size, sizeof(header->size), "%011o", 0);
    snprintf(header->mtime, sizeof(header->mtime), "%011lo", (long)time(NULL));
    header->typeflag = REGTYPE;
    snprintf(header->magic, sizeof(header->magic), TMAGIC);
    memcpy(header->version, TVERSION, TVERSLEN);
    snprintf(header->uname, sizeof(header->uname), "user");
    snprintf(header->gname, sizeof(header->gname), "group");
    if (update_checksum)
    {
        tar_compute_checksum(header);
    }
}

void tar_generate(tar_header *header, char *content, size_t content_size, char *end_data, size_t end_size)
{
    if (update_checksum)
        tar_compute_checksum(header);
    FILE *fp = fopen("archive.tar", "wb");
    if (!fp)
    {
        perror("Failed to open archive.tar");
        return;
    }
    fwrite(header, sizeof(tar_header), 1, fp);
    if (content_size > 0)
        fwrite(content, content_size, 1, fp);
    if (end_size > 0)
        fwrite(end_data, end_size, 1, fp);
    fclose(fp);
    test_status.number_of_tar_created++;
}

void tar_generate_empty(tar_header *header)
{
    char end_data[END_BYTES] = {0};
    tar_generate(header, NULL, 0, end_data, END_BYTES);
}

void tar_print_header(tar_header *header)
{
    printf("-----Header-----\n");
    printf("Name:      %s\n", header->name);
    printf("Mode:      %s\n", header->mode);
    printf("UID:       %s\n", header->uid);
    printf("GID:       %s\n", header->gid);
    printf("Size:      %s\n", header->size);
    printf("Mtime:     %s\n", header->mtime);
    printf("Chksum:    %s\n", header->chksum);
    printf("Typeflag:  %c\n", header->typeflag);
    printf("Linkname:  %s\n", header->linkname);
    printf("Magic:     %s\n", header->magic);
    printf("Version:   %s\n", header->version);
    printf("Uname:     %s\n", header->uname);
    printf("Gname:     %s\n", header->gname);
    printf("Devmajor:  %s\n", header->devmajor);
    printf("Devminor:  %s\n", header->devminor);
    printf("Prefix:    %s\n", header->prefix);
    printf("Padding:   %s\n", header->padding);
    printf("-----End-----\n");
}