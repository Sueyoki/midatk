
#pragma once
#include <cryptopp/dh.h>
using CryptoPP::DH;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/nbtheory.h>
using CryptoPP::PrimeAndGenerator;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include "cryptopp/hmac.h"
using CryptoPP::HMAC;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;

using CryptoPP::byte;
using CryptoPP::Integer;

#include <cryptopp/hex.h>
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <cryptopp/files.h>
using CryptoPP::FileSink;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;

#include <cryptopp/cryptlib.h>
using CryptoPP::AuthenticatedSymmetricCipher;
using CryptoPP::BufferedTransformation;

using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;

using CryptoPP::Redirector;

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

#include <iostream>
using std::cerr;
using std::cout;
using std::dec;
using std::endl;
using std::hex;

#include <string>
using std::string;

#include <assert.h>
#include "lengths.h"
#include "msg_type.h"

#ifdef USE_DEFAULT_GPQ
// RFC 5114, 1024-bit MODP Group with 160-bit Prime Order Subgroup
// http://tools.ietf.org/html/rfc5114#section-2.1
inline const Integer p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
                       "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
                       "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
                       "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
                       "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
                       "DF1FB2BC2E4A4371");

inline const Integer g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
                       "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
                       "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
                       "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
                       "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
                       "855E6EEB22B3B2E5");

inline const Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");
#endif

// deal socket error
#define deal_error(sock, ret)          \
    if (ret < 0)                       \
    {                                  \
        fprintf(stderr, "[%ld]", ret); \
        perror("Error");               \
        shutdown(sock, SHUT_WR);       \
        close(sock);                   \
        return -1;                     \
    }

struct Security_param
{
    byte client_random[LEN_RANDOM_BYTES];
    byte server_random[LEN_RANDOM_BYTES];
    byte pre_master_secert[LEN_PRE_MASTER_SECRET];
    byte master_secret[LEN_MASTER_SECERT];

    // AES Keys and Ivs
    byte client_write_key[LEN_WRITE_KEY];
    byte server_write_key[LEN_WRITE_KEY];
    byte client_write_iv[LEN_WRITE_IV];
    byte server_write_iv[LEN_WRITE_IV];
};

// Pretty print bytes
void print_integer(const Integer &x, const char *label);
void print_hex_ascii_line(const u_char *payload, int len, int offset, FILE *fp = stderr);
void print_hex(const u_char *payload, int len);
void print_hex(string data);

// DH Algorithm
void dh_pqg_generate(DH &dh, size_t key_size = LEN_MODULE << 3);
void dh_key_generate(DH &dh, SecByteBlock &priv, SecByteBlock &pub);
void dh_key_generate(DH &dh, const SecByteBlock &priv, const byte *pubkey, size_t len_pubkey, Integer &agreed_key);

// AES key-gen Algorith
void P_hash(
    // IN
    const byte *secret, size_t len_secret,
    const byte *seed, size_t len_seed,
    size_t expected_len,
    // OUT
    byte *hash_out);
void PRF(
    // IN
    const byte *secret, size_t len_secret,
    const byte *label, size_t len_label,
    const byte *seed, size_t len_seed,
    size_t expected_len,
    // OUT
    byte *hash_out);
void gen_master_secret(Security_param &sp);
void gen_GCM_param(Security_param &sp);

// AES encryption & decryption
#define LEN_SALT 4
#define LEN_IV_GCM 12
#define DEFAULT_CHANNEL ""
#define AAD_CHANNEL "AAD"
string data_dec(
    const byte *cipher_all, size_t len_cipher_all,
    const Security_param *sp, bool is_from_server);
string data_enc(
    const byte *plain, size_t len_plain,
    const Security_param *sp, size_t seq_no, bool is_from_server);
