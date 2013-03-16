/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 * based on rawMD4_fmt.c code, with trivial changes by groszek.
 */

#include "sha2.h"

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"

#ifdef _OPENMP
#define OMP_SCALE			2048
#include <omp.h>
#endif

#define FORMAT_LABEL			"raw-sha256-truncated"
#define FORMAT_NAME			"Raw SHA-256 truncated"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR " " SHA2_LIB

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		125
#define CIPHERTEXT_LENGTH		64
#define SPEC_LENGTH			6

#define BINARY_SIZE			64  /* hex encoded */
#define SALT_SIZE			0

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"$SHA256$5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8$0$64", "password"},
	{"$SHA256$4898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d80000$4$64", "password"},
	{"$SHA256$047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8000000000000$12$64", "password"},
	{"$SHA256$8dc6292773603d0d6aabbdd62a11ef721d1542d8000000000000000000000000$24$64", "password"},
	{NULL}
};

static int (*saved_key_length);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)
    [(BINARY_SIZE + sizeof(ARCH_WORD_32) - 1) / sizeof(ARCH_WORD_32)];

static inline void hex_encode(unsigned char *str, int len, unsigned char *out)
{
	int i;
	for (i = 0; i < len; ++i) {
		out[0] = itoa16[str[i]>>4];
		out[1] = itoa16[str[i]&0xF];
		out += 2;
	}
}

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t;

	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt = omp_t * MIN_KEYS_PER_CRYPT;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt = omp_t * MAX_KEYS_PER_CRYPT;
#endif
	saved_key_length = mem_calloc_tiny(sizeof(*saved_key_length) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

#ifdef TDEBUG
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}
#endif

static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext, "$SHA256$", 8))
		return 0;
	return 1;
}


static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[8 + CIPHERTEXT_LENGTH + SPEC_LENGTH + 1];

	if (!strncmp(ciphertext, "$SHA256$", 8))
		return ciphertext;

	memcpy(out, "$SHA256$", 8);
	memcpy(out + 8, ciphertext, CIPHERTEXT_LENGTH + SPEC_LENGTH + 1);
	strlwr(out + 8);
	return out;
}

static int start, end, length;

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	p = strtok(ctcopy, "$");
	p = strtok(NULL, "$");
	p = strtok(NULL, "$");
	start = atoi(p);
	p = strtok(NULL, "$");
	end = atoi(p);
	length = end - start;
	MEM_FREE(keeptr);

	return (void *)"";
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + 8;
	strncpy((char*)out, p, BINARY_SIZE);

	return out;
}

static void set_key(char *key, int index)
{
	int len = strlen(key);
	saved_key_length[index] = len;
	if (len > PLAINTEXT_LENGTH)
		len = saved_key_length[index] = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, len);
}

static char *get_key(int index)
{
	saved_key[index][saved_key_length[index]] = 0;
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		SHA256_CTX ctx;
		unsigned char hash[BINARY_SIZE];
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, saved_key[index], saved_key_length[index]);
		SHA256_Final(hash, &ctx);
		hex_encode(hash, BINARY_SIZE, (unsigned char *)crypt_out[index]);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
	{
		if (!memcmp(binary, (char*)crypt_out[index] + start, length))
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, (char*)crypt_out[index] + start, length);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_rawSHA256_truncated = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		get_salt,
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
