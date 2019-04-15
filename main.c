#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <X11/X.h>
#include <X11/Xlib.h>
#include "sha256.h"

#if defined(__linux__)
#include <unistd.h>
#else
#endif

#define PW_LENGTH 32

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

int main(int argc, char** argv) {
    char* input = 0;

    if(argc < 2) {
        input = getpass("Your password: ");
    } else {
        input = argv[1];
    }

    size_t input_length = strlen(input);

    BYTE buf[SHA256_BLOCK_SIZE] = {0};

    SHA256_CTX ctx;
    sha256_init(&ctx);
	sha256_update(&ctx, input, input_length);
	sha256_final(&ctx, buf);

    BYTE in[SHA256_BLOCK_SIZE * 2] = {0};
    BYTE* aux = in;
    for(int i = 0; i < SHA256_BLOCK_SIZE; ++i) {
        aux += sprintf(aux, "%02x", buf[i]);
    }

    size_t outlen;
    char* res = base64_encode(in, SHA256_BLOCK_SIZE * 2, &outlen);

    printf("%.*s", PW_LENGTH, res);


    free(res);

    return 0;
}