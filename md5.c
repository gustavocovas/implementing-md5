#include <stdint.h>
#include <stdio.h>
#include <string.h>

// These are the constants as defined in the Step 4 of the RFC
// First the shift amounts:
static uint32_t S[] = {7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 7,
                       12, 17, 22, 5,  9,  14, 20, 5,  9,  14, 20, 5,  9,
                       14, 20, 5,  9,  14, 20, 4,  11, 16, 23, 4,  11, 16,
                       23, 4,  11, 16, 23, 4,  11, 16, 23, 6,  10, 15, 21,
                       6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21};

// And then the 64-element table constructed from the sine function:
static uint32_t K[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

// These are the auxiliary functions defined in step 4 of the RFC:
#define F(X, Y, Z) ((X & Y) | (~X & Z))
#define G(X, Y, Z) ((X & Z) | (Y & ~Z))
#define H(X, Y, Z) (X ^ Y ^ Z)
#define I(X, Y, Z) (Y ^ (X | ~Z))

int leftrotate(int x, int offset) {
  unsigned int y = x;
  return (y << offset) | (y >> (32 - offset));
}

uint32_t to_32bit_word(uint8_t *a, int offset) {
  return (uint32_t)(a[offset + 3]) << 24 | (uint32_t)(a[offset + 2]) << 16 |
         (uint32_t)(a[offset + 1]) << 8 | (uint32_t)(a[offset]);
}

// This is the step that should be done for each 16-word block, as described in
// the RFC. This particular implementation is extracted from
// https://github.com/Zunawe/md5-c/blob/main/md5.c
void md5Step(uint32_t *buffer, uint32_t *input) {
  uint32_t AA = buffer[0];
  uint32_t BB = buffer[1];
  uint32_t CC = buffer[2];
  uint32_t DD = buffer[3];

  uint32_t E;

  unsigned int j;

  for (unsigned int i = 0; i < 64; ++i) {
    switch (i / 16) {
      case 0:
        E = F(BB, CC, DD);
        j = i;
        break;
      case 1:
        E = G(BB, CC, DD);
        j = ((i * 5) + 1) % 16;
        break;
      case 2:
        E = H(BB, CC, DD);
        j = ((i * 3) + 5) % 16;
        break;
      default:
        E = I(BB, CC, DD);
        j = (i * 7) % 16;
        break;
    }

    uint32_t temp = DD;
    DD = CC;
    CC = BB;
    BB = BB + leftrotate(AA + E + K[i] + input[j], S[i]);
    AA = temp;
  }

  buffer[0] += AA;
  buffer[1] += BB;
  buffer[2] += CC;
  buffer[3] += DD;
}

void md5(uint8_t *input, uint8_t *result) {
  // The Step 1 and 2 of the RFC tell us to append padding bits (section 3.1)
  // and append message length (section 3.2). However, in an actual
  // implementation, it is easier to just start processing the input in blocks
  // and to leave these steps to the end.

  // The Step 3 is to initialize the MD5 buffer, which stores the intermediate
  // results, as described in section 3.3. The buffer is initialized with four
  // words:
  //   word A: 01 23 45 67
  //   word B: 89 ab cd ef
  //   word C: fe dc ba 98
  //   word D: 76 54 32 10
  // Those are written with the low-order bytes first. When writing those as C
  // hexadecimal numbers, they look like this:
  uint32_t md5_buffer[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};

  uint64_t total_bytes_processed = 0;
  size_t input_len = strlen((char *)input);

  // The Step 4 consist in procesing the message in 512-bit blocks.
  // For each block, we call md5_step function to update the MD5 buffer.
  for (unsigned i = 0; i + 64 < input_len; i += 64) {
    // The md5_step function receives its input via an input buffer
    uint32_t md5_step_input_buffer[16];

    for (unsigned int j = 0; j < 16; ++j) {
      // The buffer should be of 32-bit little-endian words,
      // so we convert it while filling the md5_step_input_buffer
      md5_step_input_buffer[j] = to_32bit_word(input, i + j * 4);
    }

    md5Step(md5_buffer, md5_step_input_buffer);
    total_bytes_processed += 64;
  }

  // Now there are no more full 64-byte blocks remaining. It is a good time to
  // perform steps 1 and 2.

  // However, we should consider the case where the remaining bytes, the padding
  // bits and the message length do not fit in a 512-bit block. Let's allocate
  // space for two whole blocks. We later decide if we need to call md5_step on
  // just the first block or both.

  // Our implementation will not deal with incomplete bytes when append padding
  // bits. Since we will operate on bytes rather than 32-bit words, it is easier
  // to allocate the last blocks as uint8.
  uint8_t last_blocks[128];

  // Let's also keep track of how much bytes we filled in last_blocks:
  unsigned bytes_last_blocks = 0;

  // Now fill the last blocks with the original message.
  for (unsigned i = total_bytes_processed; i < input_len; ++i) {
    last_blocks[bytes_last_blocks] = input[i];
    bytes_last_blocks++;
  }

  // If we got more than 56 bytes, the padding bits and the message length will
  // not fit on the first block.
  int needs_both_blocks = bytes_last_blocks > 56 ? 1 : 0;

  // Let's append the padding bits, as per step 1.
  last_blocks[bytes_last_blocks] = 0x80;
  bytes_last_blocks++;
  for (; bytes_last_blocks < 128; ++bytes_last_blocks) {
    last_blocks[bytes_last_blocks] = 0x00;
  }

  if (needs_both_blocks) {
    // We know that the message length won't fit in the first block. Let's call
    // md5_step on the first block then:
    uint32_t input_buffer[16];
    for (unsigned int j = 0; j < 16; ++j) {
      input_buffer[j] = to_32bit_word(last_blocks, j * 4);
    }

    md5Step(md5_buffer, input_buffer);
    total_bytes_processed += 64;

    // Now let's prepare input_buffer with the second block of last_blocks
    for (unsigned int j = 0; j < 14; ++j) {
      input_buffer[j] = to_32bit_word(last_blocks, 64 + j * 4);
    }
    // Add the 64-bit representation of the message length in the end of
    // input_buffer:
    input_buffer[14] = (uint32_t)(input_len * 8);
    input_buffer[15] = (uint32_t)((input_len * 8) >> 32);

    // Final call to md5_step
    md5Step(md5_buffer, input_buffer);
    total_bytes_processed += 64;
  } else {
    // This is the easier case. We are sure that the padding bits and the
    // message length will fit in the first block of last_blocks.

    // Let's prepare input_buffer with the first of the last_blocks
    uint32_t input_buffer[16];
    for (unsigned int j = 0; j < 14; ++j) {
      input_buffer[j] = to_32bit_word(last_blocks, j * 4);
    }

    // And then add the 64-bit representation of the message length:
    input_buffer[14] = (uint32_t)(input_len * 8);
    input_buffer[15] = (uint32_t)((input_len * 8) >> 32);

    // Final call to md5_step
    md5Step(md5_buffer, input_buffer);
    total_bytes_processed += 64;
  }

  // We are done! We just need to copy the md5_buffer into result, converting it
  // back to uint8
  for (unsigned int i = 0; i < 4; ++i) {
    result[(i * 4) + 0] = (uint8_t)((md5_buffer[i] & 0x000000FF));
    result[(i * 4) + 1] = (uint8_t)((md5_buffer[i] & 0x0000FF00) >> 8);
    result[(i * 4) + 2] = (uint8_t)((md5_buffer[i] & 0x00FF0000) >> 16);
    result[(i * 4) + 3] = (uint8_t)((md5_buffer[i] & 0xFF000000) >> 24);
  }
}

void digest_and_display(char *message, char *expected_digest) {
  uint8_t result[16];
  md5((uint8_t *)message, result);

  printf("message =%s\n", message);
  printf("expected=%s\n", expected_digest);
  printf("result  =");
  for (unsigned int i = 0; i < 16; ++i) {
    printf("%02x", result[i]);
  }
  printf("\n");
}

int main() {
  digest_and_display("", "d41d8cd98f00b204e9800998ecf8427e");
  digest_and_display("abc", "900150983cd24fb0d6963f7d28e17f72");
  digest_and_display("Hello, World!", "65a8e27d8879283831b664bd8b7f0ad4");
  digest_and_display(
      "Hello, world! This is a very long message, let's see which case it "
      "triggers",
      "1230651953c4adc13d4e3e345871713d");
  digest_and_display(
      "Hello, world! This is a very long message, let's see which case it "
      "triggers. Again, again, again, again, 123456789012345678901",
      "b40cb5c7cbc13ed764928da30c8e72a9");
  digest_and_display(
      "extremely-long-message-extremely-long-message-extremely-long-"
      "message-extremely-long-message-extremely-long-message-extremely-"
      "long-message-extremely-long-message-extremely-long-message-"
      "extremely-long-message",
      "0e45ed9e1a8538a974be2d073e0433fd");

  return 0;
}