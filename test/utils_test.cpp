
#include "../include/utils.h"

#include <stdexcept>
using std::runtime_error;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/nbtheory.h>
using CryptoPP::ModularExponentiation;
using CryptoPP::PrimeAndGenerator;

#include <cryptopp/dh.h>
using CryptoPP::DH;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include <string>
using std::string;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/cryptlib.h>
using CryptoPP::AuthenticatedSymmetricCipher;
using CryptoPP::BufferedTransformation;

using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::Redirector;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;

#include "assert.h"

int test_DH()
{
    try
    {
        // RFC 5114, 1024-bit MODP Group with 160-bit Prime Order Subgroup
        // http://tools.ietf.org/html/rfc5114#section-2.1
        // Integer p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
        // 	"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
        // 	"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
        // 	"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
        // 	"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
        // 	"DF1FB2BC2E4A4371");

        // Integer g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
        // 	"D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
        // 	"160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
        // 	"909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
        // 	"D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
        // 	"855E6EEB22B3B2E5");

        // Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");

        // Schnorr Group primes are of the form p = rq + 1, p and q prime. They
        // provide a subgroup order. In the case of 1024-bit MODP Group, the
        // security level is 80 bits (based on the 160-bit prime order subgroup).

        // For a compare/contrast of using the maximum security level, see
        // dh-agree.zip. Also see http://www.cryptopp.com/wiki/Diffie-Hellman
        // and http://www.cryptopp.com/wiki/Security_level .

        AutoSeededRandomPool prng;
        Integer p, q, g;
        PrimeAndGenerator pg;
        pg.Generate(1, prng, 512, 511);

        // 两个大素数p、q，其中p为公共模数
        p = pg.Prime();
        q = pg.SubPrime();

        // g即为Diffie-Hellman中的base: α
        g = pg.Generator();

        DH dhA, dhB;
        AutoSeededRandomPool rndA, rndB;

        dhA.AccessGroupParameters().Initialize(p, g);
        dhB.AccessGroupParameters().Initialize(p, g);

        if (!dhA.GetGroupParameters().ValidateGroup(rndA, 3) ||
            !dhB.GetGroupParameters().ValidateGroup(rndB, 3))
            throw runtime_error("Failed to validate prime and generator");

        size_t count = 0;

        p = dhA.GetGroupParameters().GetModulus();
        q = dhA.GetGroupParameters().GetSubgroupOrder();
        g = dhA.GetGroupParameters().GetGenerator();

        // http://groups.google.com/group/sci.crypt/browse_thread/thread/7dc7eeb04a09f0ce
        Integer v = ModularExponentiation(g, q, p);
        if (v != Integer::One())
            throw runtime_error("Failed to verify order of the subgroup");

        //////////////////////////////////////////////////////////////

        SecByteBlock privA(dhA.PrivateKeyLength());
        SecByteBlock pubA(dhA.PublicKeyLength());
        dhA.GenerateKeyPair(rndA, privA, pubA);

        print_integer(p, "p");
        std::cout << "pubA: ";
        print_hex(pubA.BytePtr(), pubA.SizeInBytes());

        SecByteBlock privB(dhB.PrivateKeyLength());
        SecByteBlock pubB(dhB.PublicKeyLength());
        dhB.GenerateKeyPair(rndB, privB, pubB);

        //////////////////////////////////////////////////////////////

        if (dhA.AgreedValueLength() != dhB.AgreedValueLength())
            throw runtime_error("Shared secret size mismatch");

        SecByteBlock sharedA(dhA.AgreedValueLength()), sharedB(dhB.AgreedValueLength());

        if (!dhA.Agree(sharedA, privA, pubB))
            throw runtime_error("Failed to reach shared secret (1A)");

        if (!dhB.Agree(sharedB, privB, pubA))
            throw runtime_error("Failed to reach shared secret (B)");

        count = std::min(dhA.AgreedValueLength(), dhB.AgreedValueLength());
        if (!count || 0 != memcmp(sharedA.BytePtr(), sharedB.BytePtr(), count))
            throw runtime_error("Failed to reach shared secret");

        //////////////////////////////////////////////////////////////

        Integer a, b;

        a.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());
        cout << "Shared secret (A): " << std::hex << a << endl;

        b.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());
        cout << "Shared secret (B): " << std::hex << b << endl;
    }

    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        return -2;
    }

    catch (const std::exception &e)
    {
        cerr << e.what() << endl;
        return -1;
    }

    return 0;
}

int test_GCM()
{
    // The test vectors use both ADATA and PDATA. However,
    //  as a drop in replacement for older modes such as
    //  CBC, we only exercise (and need) plain text.

    AutoSeededRandomPool prng;

    byte key[AES::DEFAULT_KEYLENGTH];
    prng.GenerateBlock(key, sizeof(key));

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    const int TAG_SIZE = 12;

    // Plain text
    string pdata = "Authenticated Encryption";

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered plain text
    string rpdata;

    /*********************************\
    \*********************************/

    // Pretty print
    encoded.clear();
    StringSource(key, sizeof(key), true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    cout << "key: " << encoded << endl;

    // Pretty print
    encoded.clear();
    StringSource(iv, sizeof(iv), true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    cout << " iv: " << encoded << endl;

    cout << endl;

    /*********************************\
    \*********************************/

    try
    {
        cout << "plain text: " << pdata << endl;

        GCM<AES>::Encryption e;
        e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        // e.SpecifyDataLengths( 0, pdata.size(), 0 );

        StringSource(pdata, true,
                     new AuthenticatedEncryptionFilter(e,
                                                       new StringSink(cipher), false, TAG_SIZE) // AuthenticatedEncryptionFilter
        );                                                                                      // StringSource
    }
    catch (CryptoPP::InvalidArgument &e)
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::Exception &e)
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    /*********************************\
    \*********************************/

    // Pretty print
    encoded.clear();
    StringSource(cipher, true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    cout << "cipher text: " << encoded << endl;

    // Attack the first and last byte
    //if( cipher.size() > 1 )
    //{
    // cipher[ 0 ] |= 0x0F;
    // cipher[ cipher.size()-1 ] |= 0x0F;
    //}

    /*********************************\
    \*********************************/

    try
    {
        GCM<AES>::Decryption d;
        d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        // d.SpecifyDataLengths( 0, cipher.size()-TAG_SIZE, 0 );

        AuthenticatedDecryptionFilter df(d,
                                         new StringSink(rpdata),
                                         AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
                                         TAG_SIZE); // AuthenticatedDecryptionFilter

        // The StringSource dtor will be called immediately
        //  after construction below. This will cause the
        //  destruction of objects it owns. To stop the
        //  behavior so we can get the decoding result from
        //  the DecryptionFilter, we must use a redirector
        //  or manually Put(...) into the filter without
        //  using a StringSource.
        StringSource(cipher, true,
                     new Redirector(df /*, PASS_EVERYTHING */)); // StringSource

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        bool b = df.GetLastResult();
        assert(true == b);

        cout << "recovered text: " << rpdata << endl;
    }
    catch (CryptoPP::HashVerificationFilter::HashVerificationFailed &e)
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::InvalidArgument &e)
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch (CryptoPP::Exception &e)
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    /*********************************\
    \*********************************/

    return 0;
}

int test_GCM_AAD()
{
    //KEY 0000000000000000000000000000000000000000000000000000000000000000
    //IV  000000000000000000000000
    //HDR 00000000000000000000000000000000
    //PTX 00000000000000000000000000000000
    //CTX cea7403d4d606b6e074ec5d3baf39d18
    //TAG ae9b1771dba9cf62b39be017940330b4

    // Test Vector 003
    byte key[32];
    memset(key, 0, sizeof(key));
    byte iv[12];
    memset(iv, 0, sizeof(iv));

    string adata(16, (char)0x00);
    string pdata = "hahahaha1234567";

    const int TAG_SIZE = 16;

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered
    string radata, rpdata;

    /*********************************\
    \*********************************/

    try
    {
        GCM<AES>::Encryption e;
        e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        // Not required for GCM mode (but required for CCM mode)
        // e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );

        AuthenticatedEncryptionFilter ef(e,
                                         new StringSink(cipher), false, TAG_SIZE); // AuthenticatedEncryptionFilter

        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: "" (empty) and "AAD"
        //   channel "" is encrypted and authenticated
        //   channel "AAD" is authenticated
        ef.ChannelPut("AAD", (const byte *)adata.data(), adata.size());
        ef.ChannelMessageEnd("AAD");

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data. Otherwise
        //  we must catch the BadState exception
        ef.ChannelPut("", (const byte *)pdata.data(), pdata.size());
        ef.ChannelMessageEnd("");

        // Pretty print
        StringSource(cipher, true,
                     new HexEncoder(new StringSink(encoded), true, 16, " "));
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

    /*********************************\
    \*********************************/

    // Attack the first and last byte
    //if( cipher.size() > 1 )
    //{
    //  cipher[ 0 ] |= 0x0F;
    //  cipher[ cipher.size()-1 ] |= 0x0F;
    //}

    /*********************************\
    \*********************************/

    try
    {
        GCM<AES>::Decryption d;
        d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

        // Break the cipher text out into it's
        //  components: Encrypted Data and MAC Value
        string enc = cipher.substr(0, cipher.length() - TAG_SIZE);
        string mac = cipher.substr(cipher.length() - TAG_SIZE);
        // Sanity checks
        assert(cipher.size() == enc.size() + mac.size());
        assert(enc.size() == pdata.size());
        assert(TAG_SIZE == mac.size());

        // Not recovered - sent via clear channel
        radata = adata;

        // Object will not throw an exception
        //  during decryption\verification _if_
        //  verification fails.
        //AuthenticatedDecryptionFilter df( d, NULL,
        // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

        // ====================================================
        cerr << "adata: " << endl;
        print_hex((byte *)adata.data(), adata.size());
        cerr << "cipher:" << endl;
        print_hex(cipher);
        cerr << "mac: " << endl;
        print_hex(mac);
        // ====================================================
        AuthenticatedDecryptionFilter df(d, NULL,
                                         AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                                             AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                                         TAG_SIZE);

        // The order of the following calls are important
        df.ChannelPut("", (const byte *)mac.data(), mac.size());
        df.ChannelPut("AAD", (const byte *)adata.data(), adata.size());
        df.ChannelPut("", (const byte *)enc.data(), enc.size());

        // If the object throws, it will most likely occur
        //  during ChannelMessageEnd()
        df.ChannelMessageEnd("AAD");
        df.ChannelMessageEnd("");

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        bool b = false;
        b = df.GetLastResult();
        assert(true == b);

        // Remove data from channel
        string retrieved;
        size_t n = (size_t)-1;

        // Plain text recovered from enc.data()
        df.SetRetrievalChannel("");
        n = (size_t)df.MaxRetrievable();
        retrieved.resize(n);

        if (n > 0)
        {
            df.Get((byte *)retrieved.data(), n);
        }
        rpdata = retrieved;
        assert(rpdata == pdata);

        // Hmmm... No way to get the calculated MAC
        //  mac out of the Decryptor/Verifier. At
        //  least it is purported to be good.
        //df.SetRetrievalChannel( "AAD" );
        //n = (size_t)df.MaxRetrievable();
        //retrieved.resize( n );

        //if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        //assert( retrieved == mac );

        // All is well - work with data
        cout << "Decrypted and Verified data. Ready for use." << endl;
        cout << endl;

        cout << "adata length: " << adata.size() << endl;
        cout << "pdata length: " << pdata.size() << endl;
        cout << endl;

        cout << "adata: " << adata << endl;
        cout << "pdata: " << pdata << endl;
        cout << endl;

        cout << "cipher text: " << endl
             << " " << encoded << endl;
        cout << endl;

        cout << "recovered adata length: " << radata.size() << endl;
        cout << "recovered pdata length: " << rpdata.size() << endl;
        cout << endl;

        cout << "recovered adata: " << radata << endl;
        cout << "recovered pdata: " << rpdata << endl;
        cout << endl;
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

    /*********************************\
    \*********************************/

    return 0;
}

void test_utils()
{
    char plain[13] = "hahahahha...";

    AutoSeededRandomPool rnd;

    Security_param sp;

    rnd.GenerateBlock(sp.client_write_iv, LEN_WRITE_IV);
    rnd.GenerateBlock(sp.client_write_key, LEN_WRITE_KEY);

    size_t seq_no = 1;
    string cipher;
    cipher.append((char *)&seq_no, sizeof(seq_no));
    cipher += data_enc((byte *)plain, sizeof(plain), &sp, 1, false);

    cout << "=============================================" << endl;

    string pdata;
    pdata = data_dec((byte *)cipher.data(), cipher.size(), &sp, false);
    cout << "plain: " << endl;
    print_hex((byte *)pdata.data(), pdata.size());
}

int main(int argc, char **argv)
{
    // test_GCM_AAD();
    // test_DH();

    // test_GCM_AAD();
    test_utils();
    // data_dec()
}
