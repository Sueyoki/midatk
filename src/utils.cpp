
#include "../include/utils.h"

void print_integer(const Integer &x, const char *label)
{
    cerr << label << ": " << endl;
    cerr << hex << x << endl;
    cerr << dec;
    cerr << "size: " << x.ByteCount() << endl;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset, FILE *fp)
{
    int i;
    int gap;
    const u_char *ch;

    /* offset */
    fprintf(fp, "%05d   ", offset);

    /* hex */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        fprintf(fp, "%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            fprintf(fp, " ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        fprintf(fp, " ");

    /* fill hex gap with spaces if not full line */
    if (len < 16)
    {
        gap = 16 - len;
        for (i = 0; i < gap; i++)
            fprintf(fp, "   ");
    }
    fprintf(fp, "   ");

    /* ascii (if printable) */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        if (isprint(*ch))
            fprintf(fp, "%c", *ch);
        else
            fprintf(fp, ".");
        ch++;
    }

    fprintf(fp, "\n");
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_hex(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16; /* number of bytes per line */
    int line_len;
    int offset = 0; /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width)
    {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    while (1)
    {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem -= line_len;
        /* shift pointer to remaining bytes to print */
        ch += line_len;
        /* add offset */
        offset += line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width)
        {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
}

void print_hex(string data)
{
    print_hex((byte *)data.data(), data.size());
}

void dh_pqg_generate(DH &dh, size_t key_size)
{
#ifdef USE_DEFAULT_GPQ
    dh.AccessGroupParameters().Initialize(p, q, g);
#else
    AutoSeededRandomPool rnd;
    Integer p, q, g;
    PrimeAndGenerator pg;

    pg.Generate(1, rnd, key_size, key_size - 1);

    // 两个大素数p、q，其中p为公共模数
    p = pg.Prime();
    q = pg.SubPrime();

    // g即为Diffie-Hellman中的base: α
    g = pg.Generator();

    dh.AccessGroupParameters().Initialize(p, q, g);
    if (!dh.GetGroupParameters().ValidateGroup(rnd, 3))
        throw std::runtime_error("Failed to validate prime and generator");
#endif
}

/// \brief 已知P, g产生公私钥
void dh_key_generate(DH &dh, SecByteBlock &priv, SecByteBlock &pub)
{
    AutoSeededRandomPool rnd;

    // 由于p = 2q + 1
    // 我们知道q = (p-1) / 2
    // 由网安数学基础5.1节推论2可知q为生成元g在模p下的指数
    // 因此我们有g^q % p = 1，q为子群指数(subgroup order)
    Integer _p, _q, _g;
    _p = dh.GetGroupParameters().GetModulus();
    _q = dh.GetGroupParameters().GetSubgroupOrder();
    _g = dh.GetGroupParameters().GetGenerator();

    if (ModularExponentiation(_g, _q, _p) != Integer::One())
        throw std::runtime_error("Failed to verify order of the subgroup");

    priv.resize(dh.PrivateKeyLength());
    pub.resize(dh.PublicKeyLength());
    dh.GenerateKeyPair(rnd, priv, pub);
}

/// \brief 产生协商后密钥
void dh_key_generate(DH &dh, const SecByteBlock& priv, const byte *pubkey, size_t len_pubkey, Integer &agreed_key)
{
    SecByteBlock sharedB(dh.AgreedValueLength());

    // 将字节类型pubkeyA转换为SecByteBlock类型
    SecByteBlock pubA(pubkey, len_pubkey);

    // 生成协商后的密钥sharedB
    if (!dh.Agree(sharedB, priv, pubA))
        throw std::runtime_error("Failed to reach shared secret");

    agreed_key = Integer(sharedB.BytePtr(), sharedB.SizeInBytes());
}

void P_hash(
    // IN
    const byte *secret, size_t len_secret,
    const byte *seed, size_t len_seed,
    size_t expected_len,
    // OUT
    byte *hash_out)
{
    if (expected_len <= 0)
        return;

    HMAC<SHA256> hmac(secret, len_secret);
    hmac.Update(seed, len_seed);

    byte a[HMAC<SHA256>::DIGESTSIZE];
    hmac.Final(a);

    size_t times = (size_t)ceil((double)expected_len / HMAC<SHA256>::DIGESTSIZE);

    byte *buf = new byte[times * HMAC<SHA256>::DIGESTSIZE];

    for (size_t i = 0; i < times; i++)
    {
        byte tmp[HMAC<SHA256>::DIGESTSIZE + len_seed];

        // tmp = a + seed
        memcpy(tmp, a, HMAC<SHA256>::DIGESTSIZE);
        memcpy(tmp + HMAC<SHA256>::DIGESTSIZE, seed, len_seed);

        hmac.Update(tmp, HMAC<SHA256>::DIGESTSIZE + len_seed);

        // hash_out += hmac(secret, a + seed)
        hmac.Final(buf + i * HMAC<SHA256>::DIGESTSIZE);

        // a = hmac(secret, a)
        hmac.Update(a, HMAC<SHA256>::DIGESTSIZE);
        hmac.Final(a);
    }

    memcpy(hash_out, buf, expected_len);
    delete[] buf;
}

/// \brief PRF密钥扩展
void PRF(
    // IN
    const byte *secret, size_t len_secret,
    const byte *label, size_t len_label,
    const byte *seed, size_t len_seed,
    size_t expected_len,
    // OUT
    byte *hash_out)
{
    byte tmp[len_seed + len_label];
    memcpy(tmp, label, len_label);
    memcpy(tmp + len_label, seed, len_seed);
    P_hash(secret, len_secret, tmp, len_seed + len_label, expected_len, hash_out);
}

/// \brief 扩展计算master secret
void gen_master_secret(Security_param &sp)
{
    byte seed[LEN_RANDOM_BYTES << 1];
    memcpy(seed, sp.client_random, LEN_RANDOM_BYTES);
    memcpy(seed + LEN_RANDOM_BYTES, sp.server_random, LEN_RANDOM_BYTES);
    PRF(sp.pre_master_secert, LEN_PRE_MASTER_SECRET, (byte *)"master secret", 13,
        seed, sizeof(seed), LEN_MASTER_SECERT, sp.master_secret);
}

/// \brief 扩展计算GCM参数
void gen_GCM_param(Security_param &sp)
{
    /*
    * prf_out = PRF(_master_secret, b'key expansion', _server_random + _client_random)
    *   client_write_key = prf_out[:16]
    *   server_write_key = prf_out[16:32]
    *   client_write_iv = prf_out[32:36]
    *   server_write_iv = prf_out[36:40]
    */
    byte seed[LEN_RANDOM_BYTES << 1];
    memcpy(seed, sp.server_random, LEN_RANDOM_BYTES);
    memcpy(seed + LEN_RANDOM_BYTES, sp.client_random, LEN_RANDOM_BYTES);

    byte buf[(LEN_WRITE_IV + LEN_WRITE_KEY) << 1];

    PRF(sp.master_secret, LEN_MASTER_SECERT, (byte *)"key expansion", 13,
        seed, sizeof(seed), (LEN_WRITE_IV + LEN_WRITE_KEY) << 1, buf);
    byte *pos = buf;
    memcpy(sp.client_write_key, pos, LEN_WRITE_KEY);
    memcpy(sp.server_write_key, pos += LEN_WRITE_KEY, LEN_WRITE_KEY);
    memcpy(sp.client_write_iv, pos += LEN_WRITE_KEY, LEN_WRITE_IV);
    memcpy(sp.server_write_iv, pos += LEN_WRITE_IV, LEN_WRITE_IV);
}

string data_dec(
    const byte *cipher_all, size_t len_cipher_all,
    const Security_param *sp, bool is_from_server)
{
    const byte *salt = is_from_server ? sp->server_write_iv : sp->client_write_iv;
    const byte *key = is_from_server ? sp->server_write_key : sp->client_write_key;
    const byte *explicit_nonce;
    byte iv[LEN_IV_GCM];
    byte *nonce = iv;

    explicit_nonce = cipher_all;

    // nonce = salt + explicit nonce, namely iv
    memcpy(nonce, salt, LEN_SALT);
    memcpy(nonce + LEN_SALT, explicit_nonce, LEN_TCP_BEGIN);

    try
    {
        string adata;
        GCM<AES>::Decryption d;

        d.SetKeyWithIV(key, LEN_WRITE_KEY, iv, LEN_IV_GCM);
        cerr << "key:" << endl;
        print_hex(key, LEN_WRITE_KEY);

        cerr << "iv:" << endl;
        print_hex(iv, LEN_IV_GCM);

        // Break the cipher text out into it's
        //  components: Encrypted Data and MAC Value

        string enc((char *)cipher_all + LEN_TCP_BEGIN, len_cipher_all - LEN_TCP_BEGIN - LEN_AUTH_TAG);
        string mac((char *)cipher_all + len_cipher_all - LEN_AUTH_TAG, LEN_AUTH_TAG);

        cerr << "cipher all: " << endl;
        print_hex((byte *)cipher_all, len_cipher_all);

        cerr << "enc: " << endl;
        print_hex(enc);

        cerr << "mac: " << endl;
        print_hex(mac);

        // Get AAD
        adata.append((char *)cipher_all, LEN_TCP_BEGIN);
        adata += APPLICATION_DATA; // APPLICATION DATA
        // Cipher len
        u_short word_len = len_cipher_all - LEN_TCP_BEGIN - LEN_AUTH_TAG;
        adata.append((char *)&word_len, sizeof(word_len));

        // Sanity checks
        assert(len_cipher_all - LEN_TCP_BEGIN == enc.size() + mac.size());
        // assert(enc.size() == pdata.size());
        assert(LEN_AUTH_TAG == mac.size());

        // Object will not throw an exception
        //  during decryption\verification _if_
        //  verification fails.
        // AuthenticatedDecryptionFilter df( d, NULL,
        // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

        AuthenticatedDecryptionFilter df(d, NULL,
                                         AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                                             AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                                         LEN_AUTH_TAG);

        // The order of the following calls are important
        df.ChannelPut(DEFAULT_CHANNEL, (const byte *)mac.data(), mac.size());
        df.ChannelPut(AAD_CHANNEL, (const byte *)adata.data(), adata.size());
        df.ChannelPut(DEFAULT_CHANNEL, (const byte *)enc.data(), enc.size());

        // If the object throws, it will most likely occur
        //  during ChannelMessageEnd()
        df.ChannelMessageEnd(AAD_CHANNEL);
        df.ChannelMessageEnd(DEFAULT_CHANNEL);

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        assert(df.GetLastResult());

        // Remove data from channel
        string retrieved;
        size_t n;

        // Plain text recovered from enc.data()
        df.SetRetrievalChannel(DEFAULT_CHANNEL);
        n = (size_t)df.MaxRetrievable();
        retrieved.resize(n);

        if (n > 0)
            df.Get((byte *)retrieved.data(), n);

        // Hmmm... No way to get the calculated MAC
        //  mac out of the Decryptor/Verifier. At
        //  least it is purported to be good.
        //df.SetRetrievalChannel( "AAD" );
        //n = (size_t)df.MaxRetrievable();
        //retrieved.resize( n );

        //if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        //assert( retrieved == mac );

        // All is well - work with data
        return retrieved;
    }
    catch (CryptoPP::InvalidArgument &e)
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::AuthenticatedSymmetricCipher::BadState &e)
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::HashVerificationFilter::HashVerificationFailed &e)
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    return string();
}

string data_enc(
    const byte *plain, size_t len_plain,
    const Security_param *sp, size_t seq_no, bool is_from_server)
{
    string cipher, encoded;
    // create AES-GCM nonce from salt (=Client Write IV) and explicit nonce (=first 8 Byte of encrypted data).
    const byte *salt = is_from_server ? sp->server_write_iv : sp->client_write_iv;
    const byte *explicit_nonce;
    byte *nonce;
    const byte *key = is_from_server ? sp->server_write_key : sp->client_write_key;
    byte iv[LEN_IV_GCM];

    explicit_nonce = (const byte *)&seq_no;

    // nonce = salt + explicit nonce, namely iv
    nonce = iv;
    memcpy(nonce, salt, LEN_WRITE_IV);
    memcpy(nonce + LEN_WRITE_IV, explicit_nonce, LEN_TCP_BEGIN);

    cerr << "key:" << endl;
    print_hex(key, LEN_WRITE_KEY);

    cerr << "iv:" << endl;
    print_hex(iv, sizeof(iv));

    // Get AAD
    string adata, pdata((char *)plain, len_plain);
    adata.append((char *)&seq_no, sizeof(seq_no));
    adata += APPLICATION_DATA;
    u_short word_len = len_plain;
    adata.append((char *)&word_len, sizeof(word_len));

    try
    {
        GCM<AES>::Encryption e;

        e.SetKeyWithIV(key, LEN_WRITE_KEY, iv, sizeof(iv));
        AuthenticatedEncryptionFilter ef(e,
                                         new StringSink(cipher), false, LEN_AUTH_TAG); // AuthenticatedEncryptionFilter

        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: "" (empty) and "AAD"
        //   channel "" is encrypted and authenticated
        //   channel "AAD" is authenticated

        ef.ChannelPut(AAD_CHANNEL, (byte *)adata.data(), adata.size());
        ef.ChannelMessageEnd(AAD_CHANNEL);

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data. Otherwise
        //  we must catch the BadState exception
        ef.ChannelPut(DEFAULT_CHANNEL, (byte *)plain, len_plain);
        ef.ChannelMessageEnd(DEFAULT_CHANNEL);

        // Pretty print
        StringSource(cipher, true,
                     new HexEncoder(new StringSink(encoded), true, 16, " "));

        cerr << "plain:" << endl;
        print_hex((byte *)plain, len_plain);

        cerr << "adata:" << endl;
        print_hex((byte *)adata.data(), adata.size());

        cerr << "cipher:" << endl;
        print_hex((byte *)cipher.data(), cipher.size());
        return cipher;
    }
    catch (CryptoPP::BufferedTransformation::NoChannelSupport &e)
    {
        // The tag must go in to the default channel:
        //  "unknown: this object doesn't support multiple channels"
        cerr << "Caught NoChannelSupport..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::AuthenticatedSymmetricCipher::BadState &e)
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::InvalidArgument &e)
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    return string();
}
