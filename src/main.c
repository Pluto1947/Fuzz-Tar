#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include "utils.h"
#include "constants.h"

static char *extractor_path;

/**
 * @brief Fuzz a specific field in the tar header with various test cases.
 * @param field_name Pointer to the field to fuzz.
 * @param field_size Size of the field.
 */

void fuzz_field(char *field_name, size_t field_size)
{
    tar_header header;
    tar_init_header(&header);

    // Test 1: Empty field
    strncpy(field_name, "", field_size);
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.successful_with_empty_field++;

    // Test 2: Non-ASCII field
    char non_ascii = 'Ω'; // Unicode U+03A9, may overflow (intended)
    strncpy(field_name, &non_ascii, field_size);
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.successful_with_non_ascii_field++;

    // Test 3: Non-numeric field
    char non_numeric[] = "This is not a number!";
    strncpy(field_name, non_numeric, field_size);
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.successful_with_non_numeric_field++;

    // Test 4: Too short field (random letters, one less than size)
    srand(time(NULL));
    for (int i = 0; i < (int)field_size - 2; i++)
    {
        field_name[i] = 'a' + rand() % 26;
    }
    field_name[field_size - 1] = '\0';
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.successful_with_too_short_field++;

    // Test 5: Non-octal field (all 9s)
    memset(field_name, '9', field_size - 1);
    field_name[field_size - 1] = '\0';
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.successful_with_non_octal_field++;

    // Test 6: Field cut in the middle (hald-filled with 1s)
    memset(field_name, 0, field_size);
    memset(field_name, '1', field_size / 2);
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.successful_with_field_cut_in_middle++;

    // Test 7: Field not terminated by null byte (all 5s)
    memset(field_name, '5', field_size);
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.successful_with_field_not_terminated_null_byte++;

    // Test 8: Null byte in middle (full nulls)
    memset(field_name, 0, field_size);
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.successful_with_null_byte_in_middle++;

    // Test 9: Null byte in middle (half nulls, half 0s)
    memset(field_name, 0, field_size);
    memset(field_name, '0', field_size / 2);
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.successful_with_no_null_bytes++;

    // Test 10: Null byte in middle (all 0s, last byte null)
    memset(field_name, '0', field_size - 1);
    field_name[field_size - 1] = '\0';
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.successful_with_null_byte_in_middle++;

    // Test 11: Null byte in middle (all nulls, last byte 0)
    memset(field_name, 0, field_size - 1);
    field_name[field_size - 1] = '0';
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.successful_with_null_byte_in_middle++;

    // Test 12: No null bytes (replace nulls with spaces)
    size_t first_term = strnlen(field_name, field_size);
    if (first_term < field_size)
    {
        memset(field_name + first_term, ' ', field_size - first_term);
    }
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.successful_with_no_null_bytes++;

    // Test 13: Special characters
    char special_chars[] = {'\"', '\'', ' ', '\t', '\r', '\n', '\v', '\f', '\b'};
    for (int i = 0; i < sizeof(special_chars); i++)
    {
        memset(field_name, special_chars[i], field_size - 1);
        field_name[field_size - 1] = '\0';
        tar_generate_empty(&header);
        if (run_extractor(extractor_path))
            test_status.successful_with_special_character++;
    }

    // Test 14: Negative value
    snprintf(field_name, field_size, "%d", INT_MIN);
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.successful_with_negative_value++;
}

/**
 * @brief Fuzz the 'name' field of the tar header.
 */
void fuzz_name()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing Name ~~~\n");
    int prev_success = test_status.number_of_success;
    fuzz_field(header.name, sizeof(header.name));
    test_status.name_fuzzing_success = test_status.number_of_success - prev_success;
    printf("~~~ Name Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'mode' field of the tar header.
 */
void fuzz_mode()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing Mode ~~~\n");
    int prev_success = test_status.number_of_success;
    fuzz_field(header.mode, sizeof(header.mode));

    int modes[] = {TSUID, TSGID, TSVTX, TUREAD, TUWRITE, TUEXEC, TGREAD, TGWRITE, TGEXEC, TOREAD, TOWRITE, TOEXEC};
    for (int i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
    {
        tar_init_header(&header);
        snprintf(header.mode, sizeof(header.mode), "%o", modes[i]);
        tar_generate_empty(&header);
        run_extractor(extractor_path);
    }
    test_status.mode_fuzzing_success = test_status.number_of_success - prev_success;
    printf("~~~ Mode Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'uid' field of the tar header.
 */
void fuzz_uid()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing UID ~~~\n");
    int prev_success = test_status.number_of_success;
    fuzz_field(header.uid, sizeof(header.uid));
    test_status.uid_fuzzing_success = test_status.number_of_success - prev_success;
    printf("~~~ UID Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'gid' field of the tar header.
 */
void fuzz_gid()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing GID ~~~\n");
    int prev_success = test_status.number_of_success;
    fuzz_field(header.gid, sizeof(header.gid));
    test_status.gid_fuzzing_success = test_status.number_of_success - prev_success;
    printf("~~~ GID Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'size' field of the tar header.
 */
void fuzz_size()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing Size ~~~\n");
    int prev_success = test_status.number_of_success;
    fuzz_field(header.size, sizeof(header.size));

    char content[] = "This is a test file content.";
    size_t content_size = sizeof(content); // Includes null terminator
    int num_tries = 10;
    int possible_sizes[num_tries];
    srand(time(NULL));
    for (int i = 0; i < num_tries; i++)
    {
        possible_sizes[i] = rand() % BLOCK_SIZE;
    }
    for (int i = 0; i < num_tries; i++)
    {
        tar_init_header(&header);
        char end_data[BLOCK_SIZE] = {0};
        snprintf(header.size, sizeof(header.size), "%o", possible_sizes[i]);
        tar_generate(&header, content, content_size, end_data, BLOCK_SIZE);
        run_extractor(extractor_path);
    }
    tar_init_header(&header);
    snprintf(header.size, sizeof(header.size), "%d", INT_MIN);
    char end_data[BLOCK_SIZE] = {0};
    tar_generate(&header, content, content_size, end_data, BLOCK_SIZE);
    if (run_extractor(extractor_path))
        test_status.successful_with_negative_value++;

    test_status.size_fuzzing_success = test_status.number_of_success - prev_success;
    printf("~~~ Size Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'mtime' field of the tar header.
 */
void fuzz_mtime()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing Mtime ~~~\n");
    int prev_success = test_status.number_of_success;
    fuzz_field(header.mtime, sizeof(header.mtime));

    time_t now = time(NULL);
    time_t times[] = {INT_MIN, -300, 300, now - (365 * 24 * 60 * 60), now, now + (30 * 24 * 60 * 60), now + INT_MAX, LLONG_MAX};
    for (int i = 0; i < sizeof(times) / sizeof(times[0]); i++)
    {
        tar_init_header(&header);
        snprintf(header.mtime, sizeof(header.mtime), "%lo", (unsigned long)times[i]);
        tar_generate_empty(&header);
        run_extractor(extractor_path);
    }
    test_status.mtime_fuzzing_success = test_status.number_of_success - prev_success;
    printf("~~~ Mtime Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'chksum' field of the tar header.
 */
void fuzz_checksum()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing Checksum ~~~\n");
    int prev_success = test_status.number_of_success;
    update_checksum = 0; // Disable checksum updates
    fuzz_field(header.chksum, sizeof(header.chksum));

    char content[] = "Checksum fuzzinf data.";
    size_t content_size = sizeof(content); // Includes null terminator
    char end_data[BLOCK_SIZE] = {0};
    tar_init_header(&header);
    memset(header.chksum, 0, sizeof(header.chksum));
    tar_generate(&header, content, content_size, end_data, BLOCK_SIZE);
    run_extractor(extractor_path);

    update_checksum = 1; // Re-enable checksum updates
    test_status.checksum_fuzzing_success = test_status.number_of_success - prev_success;
    printf("~~~ Checksum Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'typeflag' field of the tar header.
 */
void fuzz_typeflag()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing Typeflag ~~~\n");
    int prev_success = test_status.number_of_success;

    for (int i = 0; i < 256; i++)
    {
        tar_init_header(&header);
        header.typeflag = i;
        tar_generate_empty(&header);
        run_extractor(extractor_path);
    }
    tar_init_header(&header);
    header.typeflag = -1;
    tar_generate_empty(&header);
    run_extractor(extractor_path);

    tar_init_header(&header);
    header.typeflag = '日'; // Non-ASCII, may overflow (intended)
    tar_generate_empty(&header);
    run_extractor(extractor_path);

    test_status.typeflag_fuzzing_success = test_status.number_of_success - prev_success;
    printf("~~~ Typeflag Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'linkname' field of the tar header.
 */
void fuzz_linkname()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing Linkname ~~~\n");
    int prev_success = test_status.number_of_success;
    fuzz_field(header.linkname, sizeof(header.linkname));
    test_status.linkname_fuzzing_success = test_status.number_of_success - prev_success;
    printf("~~~ Linkname Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'magic' field of the tar header.
 */
void fuzz_magic()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing Magic ~~~\n");
    int prev_success = test_status.number_of_success;
    fuzz_field(header.magic, sizeof(header.magic));
    test_status.magic_fuzzing_success = test_status.number_of_success - prev_success;
    printf("~~~ Magic Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'version' field of the tar header.
 */
void fuzz_version()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing Version ~~~\n");
    int prev_success = test_status.number_of_success;
    fuzz_field(header.version, sizeof(header.version));

    char octal[3] = {'0', '0', '\0'};
    for (int i = 0; i < 8; i++)
    {
        octal[0] = i + '0';
        for (int j = 0; j < 8; j++)
        {
            octal[1] = j + '0';
            tar_init_header(&header);
            snprintf(header.version, sizeof(header.version), "%s", octal);
            tar_generate_empty(&header);
            run_extractor(extractor_path);
        }
    }
    test_status.version_fuzzing_success = test_status.number_of_success - prev_success;
    printf("~~~ Version Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'uname' field of the tar header.
 */
void fuzz_uname()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing Uname ~~~\n");
    int prev_success = test_status.number_of_success;
    fuzz_field(header.uname, sizeof(header.uname));
    test_status.uname_fuzzing_success = test_status.number_of_success - prev_success;
    printf("~~~ Uname Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'gname' field of the tar header.
 */
void fuzz_gname()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing Gname ~~~\n");
    int prev_success = test_status.number_of_success;
    fuzz_field(header.gname, sizeof(header.gname));
    test_status.gname_fuzzing_success = test_status.number_of_success - prev_success;
    printf("~~~ Gname Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'end of file' field of the tar header.
 */
void fuzz_end_of_file()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing End of File ~~~\n");
    int prev_success = test_status.number_of_success;

    int end_sizes[] = {0, 1, END_BYTES / 4, END_BYTES / 2, END_BYTES - 1, END_BYTES, END_BYTES + 1, END_BYTES * 2, END_BYTES * 4};
    char content[] = "End of file test data.";
    size_t content_size = sizeof(content); // Includes null terminator
    char end_data[END_BYTES * 4] = {0};

    for (int i = 0; i < sizeof(end_sizes) / sizeof(end_sizes[0]); i++)
    {
        tar_init_header(&header);
        tar_generate(&header, NULL, 0, end_data, end_sizes[i]);
        run_extractor(extractor_path);

        tar_init_header(&header);
        snprintf(header.size, sizeof(header.size), "%o", (unsigned int)content_size);
        tar_generate(&header, content, content_size, end_data, end_sizes[i]);
        run_extractor(extractor_path);
    }
    test_status.end_of_file_fuzzing_success = test_status.number_of_success - prev_success;
    printf("~~~ End of File Fuzzing Done ~~~\n");
}

/**
 * @brief Main entry point for the fuzzer.
 */
int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <extractor_path>\n", argv[0]);
        return 1;
    }
    extractor_path = argv[1];
    init_test_status(&test_status);

    printf("~~~ Starting Fuzzing ~~~\n");
    fuzz_name();
    fuzz_mode();
    fuzz_uid();
    fuzz_gid();
    fuzz_size();
    fuzz_mtime();
    fuzz_checksum();
    fuzz_typeflag();
    fuzz_linkname();
    fuzz_magic();
    fuzz_version();
    fuzz_uname();
    fuzz_gname();
    fuzz_end_of_file();
    printf("~~~ Fuzzing Completed ~~~\n");

    print_test_status(&test_status);
    return 0;
}