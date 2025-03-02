#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include "utils.h"

static char *extractor_path;

/**
 * @brief Fuzz the 'name' field with aggressive edge cases.
 */
void fuzz_name()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n+++ Fuzzing Name +++\n");

    // Test 1: Overflow with prefix and invalid typeflag
    memset(header.name, '\xFF', sizeof(header.name));
    memset(header.prefix, '\xFF', sizeof(header.prefix));
    header.typeflag = '\x92'; // Non-standard type
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.name_fuzzing_success++;

    // Test 2: Junk with no null and content
    memset(header.name, 'A', sizeof(header.name));
    header.name[0] = '\x01';
    header.name[sizeof(header.name) - 1] = '\xFF';
    snprintf(header.size, sizeof(header.size), "00000000001");
    char content[] = "X";
    tar_generate(&header, content, sizeof(content), NULL, 0);
    if (run_extractor(extractor_path))
        test_status.name_fuzzing_success++;

    // Test 3: Embedded nulls with huge size
    const char junk[] = "\x01\xFFinvalid\x00path";
    memcpy(header.name, junk, sizeof(junk) < sizeof(header.name) ? sizeof(junk) : sizeof(header.name));
    snprintf(header.size, sizeof(header.size), "77777777777");
    tar_generate(&header, content, sizeof(content), NULL, 0);
    if (run_extractor(extractor_path))
        test_status.name_fuzzing_success++;

    printf("+++ Name Fuzzing Done +++\n");
}
/**
 * @brief Fuzz the 'mode' field of the tar header.
 */
void fuzz_mode()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n+++ Fuzzing Mode +++\n");

    // Test 1: Max octal permissions
    snprintf(header.mode, sizeof(header.mode), "07777");
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.mode_fuzzing_success++;

    // Test 2: Non-octal mode
    snprintf(header.mode, sizeof(header.mode), "ABCDEF");
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.mode_fuzzing_success++;

    // Test 3: Overflow mode
    memset(header.mode, '9', sizeof(header.mode));
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.mode_fuzzing_success++;

    printf("+++ Mode Fuzzing Done +++\n");
}

/**
 * @brief Fuzz the 'uid' field of the tar header.
 */
void fuzz_uid()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing UID ~~~\n");

    memset(header.uid, '9', sizeof(header.uid));
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.uid_fuzzing_success++;

    snprintf(header.uid, sizeof(header.uid), "-000001"); // 7 bytes + null
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.uid_fuzzing_success++;

    snprintf(header.uid, sizeof(header.uid), "ABCDEF"); // 6 bytes + null
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.uid_fuzzing_success++;

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

    memset(header.gid, '9', sizeof(header.gid));
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.gid_fuzzing_success++;

    snprintf(header.gid, sizeof(header.gid), "-000001"); // 7 bytes + null
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.gid_fuzzing_success++;

    snprintf(header.gid, sizeof(header.gid), "GIDJUN"); // 6 bytes + null
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.gid_fuzzing_success++;

    printf("~~~ GID Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'size' field of the tar header.
 */
void fuzz_size()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n+++ Fuzzing Size +++\n");

    char content[] = "This is a test file content.";
    size_t content_size = sizeof(content);
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
        if (run_extractor(extractor_path))
            test_status.size_fuzzing_success++;
    }
    tar_init_header(&header);
    snprintf(header.size, sizeof(header.size), "%d", INT_MIN);
    char end_data[BLOCK_SIZE] = {0};
    tar_generate(&header, content, content_size, end_data, BLOCK_SIZE);
    if (run_extractor(extractor_path))
        test_status.size_fuzzing_success++;

    printf("+++ Size Fuzzing Done +++\n");
}

/**
 * @brief Fuzz the 'mtime' field with extreme and invalid values.
 */
void fuzz_mtime()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n+++ Fuzzing Mtime +++\n");

    // Test 1: Extreme overflow with valid checksum
    snprintf(header.mtime, sizeof(header.mtime), "99999999999");
    tar_compute_checksum(&header);
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.mtime_fuzzing_success++;

    // Test 2: Non-octal with multi-file
    snprintf(header.mtime, sizeof(header.mtime), "FFFFFFF");
    FILE *fp = fopen("archive.tar", "wb");
    fwrite(&header, sizeof(tar_header), 1, fp);
    tar_init_header(&header);
    fwrite(&header, sizeof(tar_header), 1, fp);
    char end[END_BYTES] = {0};
    fwrite(end, END_BYTES, 1, fp);
    fclose(fp);
    test_status.number_of_tar_created++;
    if (run_extractor(extractor_path))
        test_status.mtime_fuzzing_success++;

    // Test 3: Negative with content
    snprintf(header.mtime, sizeof(header.mtime), "-ABCDEF");
    snprintf(header.size, sizeof(header.size), "00000000001");
    char content[] = "Y";
    tar_generate(&header, content, sizeof(content), NULL, 0);
    if (run_extractor(extractor_path))
        test_status.mtime_fuzzing_success++;

    printf("+++ Mtime Fuzzing Done +++\n");
}

/**
 * @brief Fuzz the 'chksum' field with plausible but invalid values.
 */
void fuzz_chksum()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing Checksum ~~~\n");
    update_checksum = 0;

    tar_compute_checksum(&header);
    header.chksum[0] = '1';
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.checksum_fuzzing_success++;

    snprintf(header.chksum, sizeof(header.chksum), "7777777"); // 7 bytes + null
    snprintf(header.size, sizeof(header.size), "00000000001");
    char content[] = "Z";
    tar_generate(&header, content, sizeof(content), NULL, 0);
    if (run_extractor(extractor_path))
        test_status.checksum_fuzzing_success++;

    snprintf(header.chksum, sizeof(header.chksum), "XYZ123"); // 6 bytes + null
    tar_generate(&header, content, sizeof(content), NULL, 0);
    if (run_extractor(extractor_path))
        test_status.checksum_fuzzing_success++;

    update_checksum = 1;
    printf("~~~ Checksum Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'typeflag' field of the tar header.
 */
void fuzz_typeflag()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n+++ Fuzzing Typeflag +++\n");
    int prev_success = test_status.number_of_success;

    for (int i = 0; i < 256; i++)
    {
        tar_init_header(&header);
        header.typeflag = (char)i;
        tar_generate_empty(&header);
        run_extractor(extractor_path);
    }
    tar_init_header(&header);
    header.typeflag = -1;
    tar_generate_empty(&header);
    run_extractor(extractor_path);

    tar_init_header(&header);
    header.typeflag = '\xFF'; // Max single-byte value (intended overflow test)
    tar_generate_empty(&header);
    run_extractor(extractor_path);

    test_status.typeflag_fuzzing_success = test_status.number_of_success - prev_success;
    printf("+++ Typeflag Fuzzing Done +++\n");
}

/**
 * @brief Fuzz the 'linkname' field of the tar header.
 */
void fuzz_linkname()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n+++ Fuzzing Linkname +++\n");

    // Test 1: Overflow linkname
    memset(header.linkname, '\xFF', sizeof(header.linkname));
    header.typeflag = SYMTYPE; // Symbolic link
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.linkname_fuzzing_success++;

    // Test 2: No null terminator
    memset(header.linkname, 'L', sizeof(header.linkname));
    header.typeflag = SYMTYPE;
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.linkname_fuzzing_success++;

    // Test 3: Invalid link with content
    snprintf(header.linkname, sizeof(header.linkname), "/invalid/path");
    header.typeflag = SYMTYPE;
    char content[] = "Link content";
    tar_generate(&header, content, sizeof(content), NULL, 0);
    if (run_extractor(extractor_path))
        test_status.linkname_fuzzing_success++;

    printf("+++ Linkname Fuzzing Done +++\n");
}

/**
 * @brief Fuzz the 'magic' field with invalid values.
 */
void fuzz_magic()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing Magic ~~~\n");

    snprintf(header.magic, sizeof(header.magic), "BADMA"); // 5 bytes + null
    tar_compute_checksum(&header);
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.magic_fuzzing_success++;

    memset(header.magic, '\xFF', sizeof(header.magic));
    snprintf(header.size, sizeof(header.size), "00000000001");
    char content[] = "M";
    tar_generate(&header, content, sizeof(content), NULL, 0);
    if (run_extractor(extractor_path))
        test_status.magic_fuzzing_success++;

    snprintf(header.magic, sizeof(header.magic), "ust"); // 3 bytes + null
    snprintf(header.size, sizeof(header.size), "77777777777");
    tar_generate(&header, content, sizeof(content), NULL, 0);
    if (run_extractor(extractor_path))
        test_status.magic_fuzzing_success++;

    printf("~~~ Magic Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz the 'version' field of the tar header.
 */
void fuzz_version()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n+++ Fuzzing Version +++\n");

    char octal[3] = {'0', '0', '\0'};
    for (int i = 0; i < 8; i++)
    {
        octal[0] = i + '0';
        for (int j = 0; j < 8; j++)
        {
            octal[1] = j + '0';
            tar_init_header(&header);
            strncpy(header.version, octal, sizeof(header.version));
            tar_generate_empty(&header);
            if (run_extractor(extractor_path))
                test_status.version_fuzzing_success++;
        }
    }
    printf("+++ Version Fuzzing Done +++\n");
}

/**
 * @brief Fuzz the 'uname' field of the tar header.
 */
void fuzz_uname()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n+++ Fuzzing Uname +++\n");

    // Test 1: Overflow uname
    memset(header.uname, '\xFF', sizeof(header.uname));
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.uname_fuzzing_success++;

    // Test 2: No null terminator
    memset(header.uname, 'U', sizeof(header.uname));
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.uname_fuzzing_success++;

    // Test 3: Junk with nulls
    const char junk[] = "\x00user\xFFjunk";
    memcpy(header.uname, junk, sizeof(junk) < sizeof(header.uname) ? sizeof(junk) : sizeof(header.uname));
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.uname_fuzzing_success++;

    printf("+++ Uname Fuzzing Done +++\n");
}

/**
 * @brief Fuzz the 'gname' field of the tar header.
 */
void fuzz_gname()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n+++ Fuzzing Gname +++\n");

    printf("+++ Gname Fuzzing Done +++\n");
}

/**
 * @brief Fuzz the content size of the tar archive.
 */
void fuzz_huge_content()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n+++ Fuzzing Huge Content +++\n");

    // Test 1: 1MB content
    char content[1024 * 1024]; // 1MB
    memset(content, 'X', sizeof(content));
    snprintf(header.size, sizeof(header.size), "%lo", (unsigned long)sizeof(content));
    tar_generate(&header, content, sizeof(content), NULL, 0);
    if (run_extractor(extractor_path))
        test_status.huge_content_fuzzing_success++; // Fixed

    // Test 2: Huge size with short content
    snprintf(header.size, sizeof(header.size), "77777777777");
    char short_content[] = "Short";
    tar_generate(&header, short_content, sizeof(short_content), NULL, 0);
    if (run_extractor(extractor_path))
        test_status.huge_content_fuzzing_success++; // Fixed

    printf("+++ Huge Content Fuzzing Done +++\n");
}

/**
 * @brief Fuzz the 'prefix' field with overflow.
 */
void fuzz_prefix()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n+++ Fuzzing Prefix +++\n");

    // Test 1: Overflow prefix
    memset(header.prefix, '\xFF', sizeof(header.prefix));
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.prefix_fuzzing_success++; // Fixed

    // Test 2: No null terminator
    memset(header.prefix, 'P', sizeof(header.prefix));
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.prefix_fuzzing_success++; // Fixed

    printf("+++ Prefix Fuzzing Done +++\n");
}

/**
 * @brief Fuzz with corrupted padding and footer.
 */
void fuzz_padding_footer()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n+++ Fuzzing Padding and Footer +++\n");

    // Test 1: Corrupted padding
    memset(header.padding, '\xFF', sizeof(header.padding));
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.size_fuzzing_success++; // Tied to size handling

    // Test 2: Oversized footer
    char huge_end[END_BYTES * 2];
    memset(huge_end, '\xAA', sizeof(huge_end));
    tar_generate(&header, NULL, 0, huge_end, sizeof(huge_end));
    if (run_extractor(extractor_path))
        test_status.end_of_file_fuzzing_success++;

    printf("+++ Padding and Footer Fuzzing Done +++\n");
}

/**
 * @brief Fuzz combo of fields for complex crashes.
 */
void fuzz_combo()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n+++ Fuzzing Combo +++\n");

    // Test 1: Name + size + typeflag
    memset(header.name, '\xFF', sizeof(header.name));
    snprintf(header.size, sizeof(header.size), "99999999999");
    header.typeflag = '\x90';
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.name_fuzzing_success++;

    // Test 2: Linkname + prefix + chksum
    update_checksum = 0;
    tar_init_header(&header);
    memset(header.linkname, '\xFF', sizeof(header.linkname));
    memset(header.prefix, '\xFF', sizeof(header.prefix));
    snprintf(header.chksum, sizeof(header.chksum), "123456");
    header.typeflag = SYMTYPE;
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.linkname_fuzzing_success++;
    update_checksum = 1;

    printf("+++ Combo Fuzzing Done +++\n");
}

/**
 * @brief Fuzz the end-of-file marker of the tar archive.
 */
void fuzz_end_of_file()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n+++ Fuzzing End of File +++\n");
    int prev_success = test_status.number_of_success;

    int end_sizes[] = {0, 1, END_BYTES / 4, END_BYTES / 2, END_BYTES - 1, END_BYTES, END_BYTES + 1, END_BYTES * 2, END_BYTES * 4};
    char content[] = "End of file test data.";
    size_t content_size = sizeof(content);
    char end_data[END_BYTES * 4] = {0};

    for (size_t i = 0; i < sizeof(end_sizes) / sizeof(end_sizes[0]); i++)
    { // Changed to size_t
        tar_init_header(&header);
        tar_generate(&header, NULL, 0, end_data, end_sizes[i]);
        run_extractor(extractor_path);

        tar_init_header(&header);
        snprintf(header.size, sizeof(header.size), "%o", (unsigned int)content_size);
        tar_generate(&header, content, content_size, end_data, end_sizes[i]);
        run_extractor(extractor_path);
    }
    test_status.end_of_file_fuzzing_success = test_status.number_of_success - prev_success;
    printf("+++ End of File Fuzzing Done +++\n");
}

/**
 * @brief Target known crash conditions.
 */
void fuzz_known_crashes()
{
    tar_header header;
    tar_init_header(&header);
    printf("\n~~~ Fuzzing Known Crash Conditions ~~~\n");
    int prev_success = test_status.number_of_success;

    memset(header.name, '\xFF', sizeof(header.name));
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.name_fuzzing_success++;

    header.typeflag = '\x90';
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.typeflag_fuzzing_success++;

    char content[] = "Negative size test.";
    snprintf(header.size, sizeof(header.size), "-000000001"); // 10 bytes + null
    tar_generate(&header, content, sizeof(content), NULL, 0);
    if (run_extractor(extractor_path))
        test_status.size_fuzzing_success++;

    snprintf(header.mtime, sizeof(header.mtime), "77777777777");
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.mtime_fuzzing_success++;

    update_checksum = 0;
    tar_init_header(&header);
    snprintf(header.chksum, sizeof(header.chksum), "9999999"); // 7 bytes + null
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.checksum_fuzzing_success++;
    update_checksum = 1;

    memset(header.uid, '9', sizeof(header.uid));
    tar_generate_empty(&header);
    if (run_extractor(extractor_path))
        test_status.uid_fuzzing_success++;

    test_status.known_crash_fuzzing_success = test_status.number_of_success - prev_success;

    printf("~~~ Known Crash Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz multiple files in a single archive.
 */
void fuzz_multi_file()
{
    tar_header h1, h2;
    tar_init_header(&h1);
    tar_init_header(&h2);
    printf("\n~~~ Fuzzing Multi-File ~~~\n");

    snprintf(h2.size, sizeof(h2.size), "99999999999");
    memset(h2.name, '\xFF', sizeof(h2.name));
    char content[] = "Multi-file content";
    FILE *fp = fopen("archive.tar", "wb");
    fwrite(&h1, sizeof(tar_header), 1, fp);
    fwrite(&h2, sizeof(tar_header), 1, fp);
    fwrite(content, sizeof(content), 1, fp);
    char end[END_BYTES] = {0};
    fwrite(end, END_BYTES, 1, fp);
    fclose(fp);
    test_status.number_of_tar_created++;
    if (run_extractor(extractor_path))
        test_status.multi_file_fuzzing_success++;

    tar_init_header(&h1);
    tar_init_header(&h2);
    h2.typeflag = '\x91';
    char huge_content[1024 * 1024];
    memset(huge_content, 'X', sizeof(huge_content));
    snprintf(h2.size, sizeof(h2.size), "%lo", (unsigned long)sizeof(huge_content));
    fp = fopen("archive.tar", "wb");
    fwrite(&h1, sizeof(tar_header), 1, fp);
    fwrite(&h2, sizeof(tar_header), 1, fp);
    fwrite(huge_content, sizeof(huge_content), 1, fp);
    fwrite(end, END_BYTES, 1, fp);
    fclose(fp);
    test_status.number_of_tar_created++;
    if (run_extractor(extractor_path))
        test_status.multi_file_fuzzing_success++;

    tar_init_header(&h1);
    tar_init_header(&h2);
    update_checksum = 0;
    snprintf(h2.chksum, sizeof(h2.chksum), "9999999"); // 7 bytes + null
    memset(h2.prefix, '\xFF', sizeof(h2.prefix));
    fp = fopen("archive.tar", "wb");
    fwrite(&h1, sizeof(tar_header), 1, fp);
    fwrite(&h2, sizeof(tar_header), 1, fp);
    fwrite(content, sizeof(content), 1, fp);
    fwrite(end, END_BYTES, 1, fp);
    fclose(fp);
    test_status.number_of_tar_created++;
    if (run_extractor(extractor_path))
        test_status.multi_file_fuzzing_success++;
    update_checksum = 1;

    printf("~~~ Multi-File Fuzzing Done ~~~\n");
}

/**
 * @brief Fuzz everything at once for maximum chaos.
 */
void fuzz_overflow_all()
{
    tar_header header;
    memset(&header, '\xFF', sizeof(tar_header));
    snprintf(header.magic, sizeof(header.magic), "ustar");
    snprintf(header.version, sizeof(header.version), "00");
    char content[1024 * 1024];
    memset(content, '\xFF', sizeof(content));
    snprintf(header.size, sizeof(header.size), "%lo", (unsigned long)sizeof(content));
    FILE *fp = fopen("archive.tar", "wb");
    fwrite(&header, sizeof(tar_header), 1, fp);
    fwrite(content, sizeof(content), 1, fp);
    char end[END_BYTES] = {0};
    fwrite(end, END_BYTES, 1, fp);
    fclose(fp);
    test_status.number_of_tar_created++;
    if (run_extractor(extractor_path))
        test_status.size_fuzzing_success++;
    printf("+++ Overflow All Fuzzing Done +++\n");
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

    printf("\n+++ Starting Fuzzing +++\n");
    fuzz_name();
    fuzz_mode();
    fuzz_uid();
    fuzz_gid();
    fuzz_size();
    fuzz_mtime();
    fuzz_chksum();
    fuzz_typeflag();
    fuzz_linkname();
    fuzz_magic();
    fuzz_version();
    fuzz_uname();
    fuzz_gname();
    fuzz_end_of_file();
    fuzz_known_crashes();
    fuzz_multi_file();
    fuzz_huge_content();
    fuzz_prefix();
    fuzz_padding_footer();
    fuzz_combo();
    fuzz_overflow_all();
    printf("+++ Fuzzing Completed +++\n");

    print_test_status(&test_status);
    return 0;
}