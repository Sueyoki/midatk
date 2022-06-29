
// diffie hellman param length
#pragma once
#define USE_DEFAULT_GPQ

#ifdef USE_DEFAULT_GPQ
    #define LEN_MODULE 128
    #define LEN_GENERATOR 128
    #define LEN_PRIVATE_KEY LEN_MODULE
    #define LEN_PUBLIC_KEY LEN_MODULE
#else
    #define LEN_MODULE 48
    #define LEN_GENERATOR 1
    #define LEN_PRIVATE_KEY LEN_MODULE
    #define LEN_PUBLIC_KEY LEN_MODULE
#endif

#define LEN_RANDOM_BYTES 32
#define LEN_PRE_MASTER_SECRET 48
#define LEN_MASTER_SECERT 48
#define LEN_WRITE_KEY 16
#define LEN_WRITE_IV 4

// encrypt data format
#define LEN_TCP_BEGIN 8
#define LEN_AUTH_TAG 16