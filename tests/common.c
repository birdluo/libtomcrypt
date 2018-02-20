/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "common.h"

/**
  @file common.c

  Steffen Jaeckel
*/

void run_cmd(int res, int line, const char *file, const char *cmd, const char *algorithm)
{
   if (res != CRYPT_OK) {
      fprintf(stderr, "%s (%d)%s%s\n%s:%d:%s\n",
              error_to_string(res), res,
              (algorithm ? " - " : ""), (algorithm ? algorithm : ""),
              file, line, cmd);
      if (res != CRYPT_NOP) {
         exit(EXIT_FAILURE);
      }
   }
}

void print_hex(const char* what, const void* v, const unsigned long l)
{
  const unsigned char* p = v;
  unsigned long x, y = 0, z;
  fprintf(stderr, "%s contents: \n", what);
  for (x = 0; x < l; ) {
      fprintf(stderr, "%02X ", p[x]);
      if (!(++x % 16) || x == l) {
         if((x % 16) != 0) {
            z = 16 - (x % 16);
            if(z >= 8)
               fprintf(stderr, " ");
            for (; z != 0; --z) {
               fprintf(stderr, "   ");
            }
         }
         fprintf(stderr, " | ");
         for(; y < x; y++) {
            if((y % 8) == 0)
               fprintf(stderr, " ");
            if(isgraph(p[y]))
               fprintf(stderr, "%c", p[y]);
            else
               fprintf(stderr, ".");
         }
         fprintf(stderr, "\n");
      }
      else if((x % 8) == 0) {
         fprintf(stderr, " ");
      }
  }
}

/* https://stackoverflow.com/a/23898449 */
unsigned long scan_hex(const char* str, unsigned char* bytes, unsigned long blen)
{
   unsigned long pos, str_len;
   unsigned char idx0;
   unsigned char idx1;

   const unsigned char hashmap[] = {
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* 01234567 */
         0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 89:;<=>? */
         0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, /* @ABCDEFG */
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* HIJKLMNO */
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* PQRSTUVW */
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* XYZ[\]^_ */
         0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, /* `abcdefg */
   };
   if (str == NULL)
      return 0;
   str_len = strlen(str);
   for (pos = 0; ((pos + 1 < (blen * 2)) && (pos + 1 < str_len)); pos += 2) {
      idx0 = (unsigned char) (str[pos + 0] & 0x1F) ^ 0x10;
      idx1 = (unsigned char) (str[pos + 1] & 0x1F) ^ 0x10;
      bytes[pos / 2] = (unsigned char) (hashmap[idx0] << 4) | hashmap[idx1];
   }
   return pos / 2;
}

int do_compare_testvector(const void* is, const unsigned long is_len, const void* should, const unsigned long should_len, const char* what, int which)
{
   if (compare_testvector(is, is_len, should, should_len, what, which) == 0) {
      return CRYPT_OK;
   } else {
      return CRYPT_FAIL_TESTVECTOR;
   }
}

prng_state yarrow_prng;

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
