/* This driver implementation is derived from Erlang crypto_drv.c code.
 * Driver adds missed crypto functions (MD4, DES in ECB mode).
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "erl_driver.h"

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#ifndef OPENSSL_THREADS
#ifdef __GNUC__
#warning No thread support by openssl. Driver will use coarse grain locking.
#endif
#endif

#include <openssl/des.h>
#include <openssl/md4.h>

#ifdef DEBUG
#define ASSERT(e) \
    ((void) ((e) ? 1 : (fprintf(stderr,"Assert '%s' failed at %s:%d\n",\
        #e, __FILE__, __LINE__), abort(), 0)))
#else
#define ASSERT(e) ((void) 1)
#endif

#ifdef __GNUC__
#define INLINE __inline__
#else
#define INLINE
#endif

#define get_int32(s) ((((unsigned char*) (s))[0] << 24) |\
                      (((unsigned char*) (s))[1] << 16) |\
                      (((unsigned char*) (s))[2] << 8)  |\
                      (((unsigned char*) (s))[3]))

#define put_int32(s, i)\
{ (s)[0] = (char)(((i) >> 24) & 0xff);\
  (s)[1] = (char)(((i) >> 16) & 0xff);\
  (s)[2] = (char)(((i) >> 8) & 0xff);\
  (s)[3] = (char)((i) & 0xff);\
}

/* Driver interface declarations */
static int init(void);
static void finish(void);
static ErlDrvData start(ErlDrvPort port, char *command);
static void stop(ErlDrvData drv_data);
static int control(ErlDrvData drv_data, unsigned int command, char *buf,
        int len, char **rbuf, int rlen);

/* OpenSSL callbacks */
#ifdef OPENSSL_THREADS
static void locking_function(int mode, int n, const char *file, int line);
static unsigned long id_function(void);
static struct CRYPTO_dynlock_value* dyn_create_function(const char *file, int line);
static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value* ptr,
        const char *file, int line);
static void dyn_destroy_function(struct CRYPTO_dynlock_value *ptr,
        const char *file, int line);
#endif /* OPENSSL_THREADS */

static ErlDrvEntry crypto_driver_entry = {
    init,
    start,
    stop,
    NULL, /* output */
    NULL, /* ready_input */
    NULL, /* ready_output */
    "netspire_crypto_drv",
    finish,
    NULL, /* handle */
    control,
    NULL, /* timeout */
    NULL, /* outputv */

    NULL, /* ready_async */
    NULL, /* flush */
    NULL, /* call */
    NULL, /* event */
    ERL_DRV_EXTENDED_MARKER,
    ERL_DRV_EXTENDED_MAJOR_VERSION,
    ERL_DRV_EXTENDED_MINOR_VERSION,
#ifdef OPENSSL_THREADS
    ERL_DRV_FLAG_USE_PORT_LOCKING,
#else
    0,
#endif
    NULL, /* handle2 */
    NULL /* process_exit */
};

/* Keep the following definitions in alignment with the FUNC_LIST
 * in netspire_crypto.erl
 */
#define DRV_INFO                0
#define DRV_MD4                 1
#define DRV_MD4_INIT            2
#define DRV_MD4_UPDATE          3
#define DRV_MD4_FINAL           4
#define DRV_ECB_DES_ENCRYPT     5
#define DRV_ECB_DES_DECRYPT     6
#define DRV_INFO_LIB            7

#define NUM_CRYPTO_FUNCS        8

#define MD4_CTX_LEN             (sizeof(MD4_CTX))
#define MD4_LEN                 16

/* INITIALIZATION AFTER LOADING */

/*
 * This is the init function called after this driver has been loaded.
 * It must *not* be declared static.  Must return the address to
 * the driver entry.
 */
DRIVER_INIT(crypto_drv) {
    return &crypto_driver_entry;
}

/* Static locks used by OpenSSL. */
static ErlDrvRWLock** lock_vec = NULL;

/* DRIVER INTERFACE */
static int init(void) {
    ErlDrvSysInfo sys_info;
    int i;

    CRYPTO_set_mem_functions(driver_alloc, driver_realloc, driver_free);

#ifdef OPENSSL_THREADS
    driver_system_info(&sys_info, sizeof (sys_info));

    if (sys_info.scheduler_threads > 1) {
        lock_vec = driver_alloc(CRYPTO_num_locks() * sizeof (*lock_vec));
        if (lock_vec == NULL) return -1;
        memset(lock_vec, 0, CRYPTO_num_locks() * sizeof (*lock_vec));

        for (i = CRYPTO_num_locks() - 1; i >= 0; --i) {
            lock_vec[i] = erl_drv_rwlock_create("netspire_crypto_drv_stat");
            if (lock_vec[i] == NULL) return -1;
        }
        CRYPTO_set_locking_callback(locking_function);
        CRYPTO_set_id_callback(id_function);
        CRYPTO_set_dynlock_create_callback(dyn_create_function);
        CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
        CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
    }
    /* else no need for locks */
#endif /* OPENSSL_THREADS */
    return 0;
}

static void finish(void) {
    /* Moved here from control() as it's not thread safe */
    CRYPTO_cleanup_all_ex_data();

    if (lock_vec != NULL) {
        int i;
        for (i = CRYPTO_num_locks() - 1; i >= 0; --i) {
            if (lock_vec[i] != NULL) {
                erl_drv_rwlock_destroy(lock_vec[i]);
            }
        }
        driver_free(lock_vec);
    }
}

static ErlDrvData start(ErlDrvPort port, char *command) {
    set_port_control_flags(port, PORT_CONTROL_FLAG_BINARY);
    return 0; /* not used */
}

static void stop(ErlDrvData drv_data) {
    return;
}

/* Since we are operating in binary mode, the return value from control
 * is irrelevant, as long as it is not negative
 */
static int control(ErlDrvData drv_data, unsigned int command, char *buf,
        int len, char **rbuf, int rlen) {
    ErlDrvBinary *bin;
    MD4_CTX md4_ctx;
    char *p;
    const unsigned char *des_dbuf;
    const_DES_cblock *des_key;
    DES_key_schedule schedule;
    int i, dlen;

    switch (command) {
        case DRV_INFO:
            *rbuf = (char*) (bin = driver_alloc_binary(NUM_CRYPTO_FUNCS));
            for (i = 0; i < NUM_CRYPTO_FUNCS; i++) {
                bin->orig_bytes[i] = i + 1;
            }
            return NUM_CRYPTO_FUNCS;

        case DRV_MD4:
            *rbuf = (char*) (bin = driver_alloc_binary(MD4_LEN));
            MD4((unsigned char *)buf, len, (unsigned char *)bin->orig_bytes);
            return MD4_LEN;
            break;

        case DRV_MD4_INIT:
            *rbuf = (char*) (bin = driver_alloc_binary(MD4_CTX_LEN));
            MD4_Init((MD4_CTX *) bin->orig_bytes);
            return MD4_CTX_LEN;
            break;

        case DRV_MD4_UPDATE:
            if (len < MD4_CTX_LEN)
                return -1;
            *rbuf = (char*) (bin = driver_alloc_binary(MD4_CTX_LEN));
            memcpy(bin->orig_bytes, buf, MD4_CTX_LEN);
            MD4_Update((MD4_CTX *) bin->orig_bytes, buf + MD4_CTX_LEN, len - MD4_CTX_LEN);
            return MD4_CTX_LEN;
            break;

        case DRV_MD4_FINAL:
            if (len != MD4_CTX_LEN)
                return -1;
            memcpy(&md4_ctx, buf, MD4_CTX_LEN); /* XXX Use buf only? */
            *rbuf = (char *) (bin = driver_alloc_binary(MD4_LEN));
            MD4_Final((unsigned char *)bin->orig_bytes, &md4_ctx);
            return MD4_LEN;
            break;

        case DRV_ECB_DES_ENCRYPT:
        case DRV_ECB_DES_DECRYPT:
            /* buf = key[8] data */
            dlen = len - 8;
            if (dlen < 0)
                return -1;
            if (dlen % 8 != 0)
                return -1;
            des_key = (const_DES_cblock*) buf;
            des_dbuf = (unsigned char *)buf + 8;
            *rbuf = (char *) (bin = driver_alloc_binary(dlen));
            DES_set_key(des_key, &schedule);
            DES_ecb_encrypt((const_DES_cblock*) des_dbuf,
                    (DES_cblock*) bin->orig_bytes, &schedule,
                    (command == DRV_ECB_DES_ENCRYPT));
            return dlen;
            break;

        case DRV_INFO_LIB:
            /* <<DrvVer:8, NameSize:8, Name:NameSize/binary, VerNum:32, VerStr/binary>> */
        {
            static const char libname[] = "OpenSSL";
            unsigned name_sz = strlen(libname);
            const char* ver = SSLeay_version(SSLEAY_VERSION);
            unsigned ver_sz = strlen(ver);
            *rbuf = (char*) (bin = driver_alloc_binary(1 + 1 + name_sz + 4 + ver_sz));
            p = bin->orig_bytes;
            *p++ = 0; /* "driver version" for future use */
            *p++ = name_sz;
            memcpy(p, libname, name_sz);
            p += name_sz;
            put_int32(p, SSLeay()); /* OPENSSL_VERSION_NUMBER */
            p += 4;
            memcpy(p, ver, ver_sz);
        }
            return bin->orig_size;

        default:
            break;
    }
    return -1;
}

#ifdef OPENSSL_THREADS

static INLINE void locking(int mode, ErlDrvRWLock* lock) {
    switch (mode) {
        case CRYPTO_LOCK | CRYPTO_READ :
                    erl_drv_rwlock_rlock(lock);
            break;
        case CRYPTO_LOCK | CRYPTO_WRITE :
                    erl_drv_rwlock_rwlock(lock);
            break;
        case CRYPTO_UNLOCK | CRYPTO_READ :
                    erl_drv_rwlock_runlock(lock);
            break;
        case CRYPTO_UNLOCK | CRYPTO_WRITE :
                    erl_drv_rwlock_rwunlock(lock);
            break;
        default:
            ASSERT(!"Invalid lock mode");
    }
}

/* Callback from openssl for static locking
 */
static void locking_function(int mode, int n, const char *file, int line) {
    ASSERT(n >= 0 && n < CRYPTO_num_locks());
    locking(mode, lock_vec[n]);
}

/* Callback from openssl for thread id
 */
static unsigned long id_function(void) {
    return (unsigned long) erl_drv_thread_self();
}

/* Callbacks for dynamic locking, not used by current OpenSSL version (0.9.8)
 */
static struct CRYPTO_dynlock_value* dyn_create_function(const char *file, int line) {
    return (struct CRYPTO_dynlock_value*) erl_drv_rwlock_create("netspire_crypto_drv_dyn");
}

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value* ptr, const char *file, int line) {
    locking(mode, (ErlDrvRWLock*) ptr);
}

static void dyn_destroy_function(struct CRYPTO_dynlock_value *ptr, const char *file, int line) {
    return erl_drv_rwlock_destroy((ErlDrvRWLock*) ptr);
}

#endif /* OPENSSL_THREADS */
