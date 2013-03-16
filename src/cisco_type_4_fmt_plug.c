/*
 * Cracker for Cisco "type 4" hashes
 * Copyright (c) 2013 by Dhiru Kholia
 *
 * All credit goes to Sc00bz for the algorithm!
 *
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 * based on rawMD4_fmt.c code, with trivial changes by groszek.
 *
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

#define FORMAT_LABEL			"cisco4"
#define FORMAT_NAME			"Cisco \"type 4\" hashes SHA-256"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR " " SHA2_LIB

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		125
#define CIPHERTEXT_LENGTH		64

#define BINARY_SIZE			43
#define SALT_SIZE			0

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"$cisco4$OsOmQzwozC4ROs/CzpczJoShdCeW9lp7k/tGrPS5Kog", "1"},
	{"$cisco4$LcV6aBcc/53FoCJjXQMd7rBUDEpeevrK8V5jQVoJEhU", "password"},
	{"$cisco4$d7kgbEk.P6mpKdduC66fUy1BF0MImo3eyJ9uI/JbMRk", "openwall"},
	{"$cisco4$p5BSCWNS3ivUDpZlWthR.k4Q/xWqlFyEqXdaPikHenI", "2"},
	{"$cisco4$HwUf7ev9Fx84X2vvspULAeDbmwlg9jgm/Wk63kc3vfU", "11"},
	{"$cisco4$bsPEUMVATKKO9yeUlJfE3OCzHlgf0s6goJpg3P1k0UU", "test"},
	{NULL}
};

static int (*saved_key_length);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)
    [(BINARY_SIZE + sizeof(ARCH_WORD_32) - 1) / sizeof(ARCH_WORD_32)];

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

static void encode64(unsigned char *dst, unsigned char *src, int count)
{
	int i, j;
	unsigned int ch;
	unsigned char tmp;
	i = 0;
	j = 0;
	for (i = 0; i < count; i += 3)
	{
		// Get 1st byte of input
		ch  = src[i];
		tmp = itoa64[ch >> 2];
		ch  = (ch & 0x03) << 8;
		dst[j++] = tmp;
		if (i + 1 >= count)
		{
			// End of string
			dst[j++] = itoa64[ch >> 8];
			break;
		}

		// Get 2nd byte of input
		ch = ch | src[i + 1];
		tmp = itoa64[ch >> 4];
		ch = (ch & 0x0f) << 8;
		dst[j++] = tmp;
		if (i + 2 >= count)
		{
			// End of string
			dst[j++] = itoa64[ch >> 6];;
			break;
		}

		// Get 3rd byte of input
		ch  |= src[i + 2];
		tmp = itoa64[ch >> 6];
		dst[j++] = tmp;
		tmp = itoa64[ch & 0x3f];
		dst[j++] = tmp;
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext, "$cisco4$", 8))
		return 0;
	return 1;
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

static int binary_hash_0(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFF;
}

static int binary_hash_5(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFFF;
}

static int binary_hash_6(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0x7FFFFFF;
}

static int get_hash_0(int index)
{
	return crypt_out[index][0] & 0xF;
}

static int get_hash_1(int index)
{
	return crypt_out[index][0] & 0xFF;
}

static int get_hash_2(int index)
{
	return crypt_out[index][0] & 0xFFF;
}

static int get_hash_3(int index)
{
	return crypt_out[index][0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return crypt_out[index][0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	return crypt_out[index][0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	return crypt_out[index][0] & 0x7FFFFFF;
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
		unsigned char hash[32];

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, saved_key[index], saved_key_length[index]);
		SHA256_Final(hash, &ctx);
		encode64((unsigned char *)crypt_out[index], hash, SHA256_DIGEST_LENGTH);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_cisco4 = {
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
		fmt_default_split,
		get_binary,
		fmt_default_salt,
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
