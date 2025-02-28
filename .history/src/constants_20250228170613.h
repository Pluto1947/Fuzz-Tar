#ifndef CONSTANTS_H
#define CONSTANTS_H

// All values are taken from : https://www.gnu.org/software/tar/manual/html_node/Standard.html

typedef struct tar_header
{                       /* byte offset */
    char name[100];     /*   0 */
    char mode[8];       /* 100 */
    char uid[8];        /* 108 */
    char gid[8];        /* 116 */
    char size[12];      /* 124 */
    char mtime[12];     /* 136 */
    char chksum[8];     /* 148 */
    char typeflag;      /* 156 */
    char linkname[100]; /* 157 */
    char magic[6];      /* 257 */
    char version[2];    /* 263 */
    char uname[32];     /* 265 */
    char gname[32];     /* 297 */
    char devmajor[8];   /* 329 */
    char devminor[8];   /* 337 */
    char prefix[155];   /* 345 */
    char padding[12];   /* 500 */
} tar_header;           // Total size: 512 bytes

// POSIX tar constants
#define TMAGIC "ustar" /* POSIX ustar magic string (null-terminated) */
#define TMAGLEN 6      /* Length of magic string including null */
#define TVERSION "00"  /* POSIX version string (no null) */
#define TVERSLEN 2     /* Length of version string */

/* Values used in typeflag field */
#define REGTYPE '0'   /* Regular file */
#define AREGTYPE '\0' /* Alternative regular file (historical) */
#define LNKTYPE '1'   /* Hard link */
#define SYMTYPE '2'   /* Symbolic link */
#define CHRTYPE '3'   /* Character special device */
#define BLKTYPE '4'   /* Block special device */
#define DIRTYPE '5'   /* Directory */
#define FIFOTYPE '6'  /* FIFO special file */
#define CONTTYPE '7'  /* Reserved (continuation) */
#define XHDTYPE 'x'   /* Extended header for next file */
#define XGLTYPE 'g'   /* Global extended header */

/* Bits used in the mode field (octal values) */
#define TSUID 04000   /* Set UID on execution */
#define TSGID 02000   /* Set GID on execution */
#define TSVTX 01000   /* Sticky bit (reserved) */
#define TUREAD 00400  /* Read by owner */
#define TUWRITE 00200 /* Write by owner */
#define TUEXEC 00100  /* Execute/search by owner */
#define TGREAD 00040  /* Read by group */
#define TGWRITE 00020 /* Write by group */
#define TGEXEC 00010  /* Execute/search by group */
#define TOREAD 00004  /* Read by others */
#define TOWRITE 00002 /* Write by others */
#define TOEXEC 00001  /* Execute/search by others */

/* Custom constants for tar handling */
#define HEADER_LENGTH 512 /* Size of tar header in bytes */
#define BLOCK_SIZE 512    /* Size of each tar block in bytes */
#define END_BYTES 1024    /* Size of end-of-file marker (2 blocks) */

#endif