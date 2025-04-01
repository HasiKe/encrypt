#ifndef ARGON2_H
#define ARGON2_H

#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* Argon2 input parameter restrictions */
#define ARGON2_MIN_OUTLEN 4
#define ARGON2_MAX_OUTLEN 0xFFFFFFFF
#define ARGON2_MIN_TIMECOST 1
#define ARGON2_MAX_TIMECOST 0xFFFFFFFF
#define ARGON2_MIN_LANES 1
#define ARGON2_MAX_LANES 0xFFFFFF
#define ARGON2_MIN_THREADS 1
#define ARGON2_MAX_THREADS 0xFFFFFF
#define ARGON2_MIN_MEMORY 8
#define ARGON2_MAX_MEMORY_BITS 32
#define ARGON2_MAX_MEMORY 0xFFFFFFFF
#define ARGON2_MIN_SALT_LENGTH 8
#define ARGON2_MAX_SALT_LENGTH 0xFFFFFFFF
#define ARGON2_MIN_AD_LENGTH 0
#define ARGON2_MAX_AD_LENGTH 0xFFFFFFFF
#define ARGON2_MIN_SECRET_LENGTH 0
#define ARGON2_MAX_SECRET_LENGTH 0xFFFFFFFF
#define ARGON2_MIN_PWD_LENGTH 0
#define ARGON2_MAX_PWD_LENGTH 0xFFFFFFFF

/* Error codes */
typedef enum Argon2_ErrorCodes {
    ARGON2_OK = 0,
    ARGON2_OUTPUT_PTR_NULL = 1,
    ARGON2_OUTPUT_TOO_SHORT = 2,
    ARGON2_OUTPUT_TOO_LONG = 3,
    ARGON2_PWD_TOO_SHORT = 4,
    ARGON2_PWD_TOO_LONG = 5,
    ARGON2_SALT_TOO_SHORT = 6,
    ARGON2_SALT_TOO_LONG = 7,
    ARGON2_AD_TOO_SHORT = 8,
    ARGON2_AD_TOO_LONG = 9,
    ARGON2_SECRET_TOO_SHORT = 10,
    ARGON2_SECRET_TOO_LONG = 11,
    ARGON2_TIME_TOO_SMALL = 12,
    ARGON2_TIME_TOO_LARGE = 13,
    ARGON2_MEMORY_TOO_LITTLE = 14,
    ARGON2_MEMORY_TOO_MUCH = 15,
    ARGON2_LANES_TOO_FEW = 16,
    ARGON2_LANES_TOO_MANY = 17,
    ARGON2_PWD_PTR_MISMATCH = 18,
    ARGON2_SALT_PTR_MISMATCH = 19,
    ARGON2_SECRET_PTR_MISMATCH = 20,
    ARGON2_AD_PTR_MISMATCH = 21,
    ARGON2_MEMORY_ALLOCATION_ERROR = 22,
    ARGON2_FREE_MEMORY_CBK_NULL = 23,
    ARGON2_ALLOCATE_MEMORY_CBK_NULL = 24,
    ARGON2_INCORRECT_PARAMETER = 25,
    ARGON2_INCORRECT_TYPE = 26,
    ARGON2_OUT_PTR_MISMATCH = 27,
    ARGON2_THREADS_TOO_FEW = 28,
    ARGON2_THREADS_TOO_MANY = 29,
    ARGON2_MISSING_ARGS = 30,
    ARGON2_ENCODING_FAIL = 31,
    ARGON2_DECODING_FAIL = 32,
    ARGON2_THREAD_FAIL = 33,
    ARGON2_DECODING_LENGTH_FAIL = 34,
    ARGON2_VERIFY_MISMATCH = 35
} argon2_error_codes;

/* Memory allocator types --- for external allocation */
typedef int (*allocate_fptr)(uint8_t **memory, size_t bytes_to_allocate);
typedef void (*deallocate_fptr)(uint8_t *memory, size_t bytes_to_allocate);

/* Argon2 external data structures */
typedef enum Argon2_type {
    Argon2_d = 0,
    Argon2_i = 1,
    Argon2_id = 2
} argon2_type;

/* Argon2 context */
typedef struct Argon2_Context {
    uint8_t *out;    /* output array */
    uint32_t outlen; /* digest length */

    uint8_t *pwd;    /* password array */
    uint32_t pwdlen; /* password length */

    uint8_t *salt;    /* salt array */
    uint32_t saltlen; /* salt length */

    uint8_t *secret;    /* key array */
    uint32_t secretlen; /* key length */

    uint8_t *ad;    /* associated data array */
    uint32_t adlen; /* associated data length */

    uint32_t t_cost;  /* number of passes */
    uint32_t m_cost;  /* amount of memory requested (KB) */
    uint32_t lanes;   /* number of lanes */
    uint32_t threads; /* maximum number of threads */

    allocate_fptr allocate_cbk; /* pointer to memory allocator */
    deallocate_fptr free_cbk;   /* pointer to memory deallocator */

    uint32_t flags; /* array of bool options */
} argon2_context;

/* Simplified API */
int argon2i_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                     const uint32_t parallelism, const void *pwd,
                     const size_t pwdlen, const void *salt,
                     const size_t saltlen, void *hash, const size_t hashlen);

int argon2d_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                     const uint32_t parallelism, const void *pwd,
                     const size_t pwdlen, const void *salt,
                     const size_t saltlen, void *hash, const size_t hashlen);

int argon2id_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                      const uint32_t parallelism, const void *pwd,
                      const size_t pwdlen, const void *salt,
                      const size_t saltlen, void *hash, const size_t hashlen);

/* Generic function underlying the above ones */
int argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
                const uint32_t parallelism, const void *pwd,
                const size_t pwdlen, const void *salt,
                const size_t saltlen, void *hash, const size_t hashlen,
                char *encoded, const size_t encodedlen, argon2_type type,
                const uint32_t version);

int argon2_verify(const char *encoded, const void *pwd, const size_t pwdlen,
                  argon2_type type);

int argon2i_verify(const char *encoded, const void *pwd, const size_t pwdlen);

int argon2d_verify(const char *encoded, const void *pwd, const size_t pwdlen);

int argon2id_verify(const char *encoded, const void *pwd, const size_t pwdlen);

/* Core API */
int argon2_ctx(argon2_context *context, argon2_type type);

/* Error function */
const char *argon2_error_message(int error_code);

#if defined(__cplusplus)
}
#endif

#endif /* ARGON2_H */