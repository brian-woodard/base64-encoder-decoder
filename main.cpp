#include <iostream>
#include <cstdint>
#include <cassert>
#include <cstring>
#include "PrintData.h"

//Many hands make light work.
//TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu
//
//Man
//TWFu
//
//          Input                       Output
//Text        | Length | Text              | Length |  Padding
//------------|--------|-------------------|--------|---------
//light work. | 11     | bGlnaHQgd29yay4=  | 16     |    1
//light work  | 10     | bGlnaHQgd29yaw==  | 16     |    2
//light wor   | 9      | bGlnaHQgd29y      | 12     |    0
//light wo    | 8      | bGlnaHQgd28=      | 12     |    1
//light w     | 7      | bGlnaHQgdw==      | 12     |    2

//# Calculate Sec-WebSocket-Accept using Sec-WebSocket-Key
//from base64 import b64encode
//from hashlib import sha1
//from os import urandom
//# key = b64encode(urandom(16)) # Client should do this
//key = b"x3JJHMbDL1EzLkh9GBhXDw==" # Value in example request above
//magic = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11" # Protocol constant
//print(b64encode(sha1(key + magic).digest()))
//# Output: HSmrc0sMlYUkAGmm5OPpG2HaGWk=

const char encode_char[64] =
{
   'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
   'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
   'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
   'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
   'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
   'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
   'w', 'x', 'y', 'z', '0', '1', '2', '3',
   '4', '5', '6', '7', '8', '9', '+', '/',
};

const uint8_t decode_from_char[128] =
{
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62,  0,  0,  0, 63,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,
   0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,  0,  0,  0,  0,
   0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,  0,  0,  0,  0,  0,
};

///////////////////////////////////////////////////////////////////////////////
// SHA-1 Hash
// https://csrc.nist.gov/files/pubs/fips/180-3/final/docs/fips180-3_final.pdf
///////////////////////////////////////////////////////////////////////////////

// 160-bit or 20 bytes
union TSha1Hash
{
   uint32_t Word[5];
};

// 512-bit or 64 bytes
union TSha1Message
{
   uint8_t  Data[64];
   uint32_t Word[16];
};

const TSha1Hash initial_hash =
{
   0x67452301,
   0xefcdab89,
   0x98badcfe,
   0x10325476,
   0xc3d2e1f0,
};

#define SHA1CircularShift(word, bits) (((word) << (bits)) | ((word) >> (32 - (bits))))

void Swap(uint32_t* Data)
{
   *Data = (((*Data) & 0xff000000) >> 24) |
           (((*Data) & 0x00ff0000) >> 8)  |
           (((*Data) & 0x0000ff00) << 8)  |
           (((*Data) & 0x000000ff) << 24);
}

void sha1_hash_msg(const TSha1Message& Msg, TSha1Hash& Hash)
{
   uint32_t  w[80] = {};
   uint32_t  a = 0;
   uint32_t  b = 0;
   uint32_t  c = 0;
   uint32_t  d = 0;
   uint32_t  e = 0;

   // 1. Prepare message schedule
   for (size_t t = 0; t < 80; t++)
   {
      // 1. Prepare the message schedule
      if (t <= 15)
      {
         w[t] = Msg.Word[t];
         Swap(&w[t]);
      }
      else
      {
         w[t] = w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16];
         w[t] = SHA1CircularShift(w[t], 1);
      }
   }

   // 2. Initialize the working values
   a = Hash.Word[0];
   b = Hash.Word[1];
   c = Hash.Word[2];
   d = Hash.Word[3];
   e = Hash.Word[4];

   ////////////////////////////////////////////////////////////////////////////
   // SHA-1 Hash Computation for one message block (80 iterations)
   for (size_t t = 0; t < 80; t++)
   {
      uint32_t K = 0;
      uint32_t f = 0;

      if (t <= 19)
      {
         // Ch
         f = (b & c) | (~(b) & d);
         K = 0x5a827999;
      }
      else if (t <= 39)
      {
         // Parity
         f = b ^ c ^ d;
         K = 0x6ed9eba1;
      }
      else if (t <= 59)
      {
         // Maj
         f = (b & c) | (b & d) | (c & d);
         K = 0x8f1bbcdc;
      }
      else if (t <= 79)
      {
         // Parity
         f = b ^ c ^ d;
         K = 0xca62c1d6;
      }

      // 3. Calculate new working values
      uint32_t tmp = SHA1CircularShift(a, 5) + f + e + w[t] + K;
      e = d;
      d = c;
      c = SHA1CircularShift(b, 30);
      b = a;
      a = tmp;
   }

   // 4. Compute the intermediate hash value
   Hash.Word[0] += a;
   Hash.Word[1] += b;
   Hash.Word[2] += c;
   Hash.Word[3] += d;
   Hash.Word[4] += e;
}

TSha1Hash sha1_hash(const uint8_t* Input, size_t Size)
{
   TSha1Hash hash = {};
   TSha1Message msg = {};

   // Initialize hash to initial hash value
   hash = initial_hash;

   ////////////////////////////////////////////////////////////////////////////
   // Preprocessing
   uint64_t msg_size_bytes = Size;
   uint64_t msg_size_bits = msg_size_bytes * 8;

   size_t idx = 0;
   for (size_t i = 0; i < Size; i++)
   {
      msg.Data[idx] = Input[i];
      idx++;

      if (idx == 64)
      {
         sha1_hash_msg(msg, hash);
         memset(&msg, 0, sizeof(msg));
         idx = 0;
         msg.Data[idx] = Input[i];
      }
   }

   ////////////////////////////////////////////////////////////////////////////
   // Message Padding

   // Set next bit to 1
   msg.Data[idx] = 0x80;

   // Add zero bits - msg is zero'd when creating so, do nothing

   if (idx >= 56)
   {
      sha1_hash_msg(msg, hash);
      memset(&msg, 0, sizeof(msg));
      idx = 0;
   }

   // Add 64-bit length of message in bits
   uint8_t* ml = (uint8_t*)&msg_size_bits;
   for (size_t j = 0; j < 8; j++)
   {
      msg.Data[56 + j] = msg.Data[56 + j] | ml[7 - j];
   }
   // End Message Padding
   ////////////////////////////////////////////////////////////////////////////

   sha1_hash_msg(msg, hash);

   for (int i = 0; i < 5; i++)
   {
      Swap(&hash.Word[i]);
   }

   return hash;
}

std::string base64_encode(const uint8_t* Input, size_t Size)
{
   std::string output = "";

   if (Size == 0)
      return output;

   uint16_t value = 0;
   uint16_t num_bits = 0;

   for (size_t i = 0; i < Size; i++)
   {
      // Get input character
      value = (value & 0xff00) + Input[i];
      num_bits += 8;

      // Mask off top 6 bits
      uint16_t enc_value = ((0x003f << (num_bits - 6)) & value) >> (num_bits - 6);
      num_bits -= 6;
      assert(enc_value >= 0 && enc_value < 64);
      output += encode_char[enc_value];

      // Update value
      if (num_bits == 6)
      {
         value = (value & 0x003f);
         output += encode_char[value];
         num_bits = 0;
         value = 0;
      }
      else
      {
         uint16_t mask = (1 << num_bits) - 1;
         value = (value & mask) << 8;
      }
   }

   // If num_bits is non-zero, pad with required bits and add final character
   // to output string
   if (num_bits > 0)
   {
      assert(num_bits == 2 || num_bits == 4);
      value = (value >> 8) << (6 - num_bits);
      assert(value >= 0 && value < 64);
      output += encode_char[value];

      if (num_bits == 4)
      {
         // Add one padding character
         output += '=';
      }
      else if (num_bits == 2)
      {
         // Add two padding characters
         output += "==";
      }
   }

   return output;
}

std::string base64_decode(const std::string& Input)
{
   std::string output = "";

   if (Input.empty())
      return output;

   uint16_t value = 0;
   uint16_t num_bits = 0;

   for (const auto& c : Input)
   {
      // Don't decode padding
      if (c == '=')
         break;

      // Get input character
      value = ((value << 6) & 0xffc0) + (decode_from_char[(int)c] & 0x003f);
      num_bits += 6;

      if (num_bits >= 8)
      {
         // Mask off top 8 bits
         char dec_value = ((0x00ff << (num_bits - 8)) & value) >> (num_bits - 8);
         num_bits -= 8;
         output += dec_value;
      }
   }

   return output;
}

int main()
{
   // Test encoding
   printf("\n==================================\n");
   //printf("Test 'Man' encode\n");
   //std::string output = base64_encode("Man");
   //assert(output == "TWFu");

   const char* encode_str = "Many hands make light work.";
   printf("'%s' encode\n", encode_str);
   std::string output = base64_encode((const uint8_t*)encode_str, strlen(encode_str));
   printf("output '%s'\n", output.c_str());
   assert(output == "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu");

   //printf("Test 'light work.' encode\n");
   //output = base64_encode("light work.");
   //assert(output == "bGlnaHQgd29yay4=");

   //printf("Test 'light work' encode\n");
   //output = base64_encode("light work");
   //assert(output == "bGlnaHQgd29yaw==");

   //printf("Test 'light wor' encode\n");
   //output = base64_encode("light wor");
   //assert(output == "bGlnaHQgd29y");

   //printf("Test 'light wo' encode\n");
   //output = base64_encode("light wo");
   //assert(output == "bGlnaHQgd28=");

   //printf("Test 'light w' encode\n");
   //output = base64_encode("light w");
   //assert(output == "bGlnaHQgdw==");

   // Test decoding
   printf("\n==================================\n");
   printf("Test 'TWFu' decode\n");
   output = base64_decode("TWFu");
   assert(output == "Man");

   printf("Test 'TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu' decode\n");
   output = base64_decode("TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu");
   assert(output == "Many hands make light work.");

   printf("Test 'bGlnaHQgd29yay4=' decode\n");
   output = base64_decode("bGlnaHQgd29yay4=");
   assert(output == "light work.");

   printf("Test 'bGlnaHQgd29yaw==' decode\n");
   output = base64_decode("bGlnaHQgd29yaw==");
   assert(output == "light work");

   printf("Test 'bGlnaHQgd29y' decode\n");
   output = base64_decode("bGlnaHQgd29y");
   assert(output == "light wor");

   printf("Test 'bGlnaHQgd28=' decode\n");
   output = base64_decode("bGlnaHQgd28=");
   assert(output == "light wo");

   printf("Test 'bGlnaHQgdw==' decode\n");
   output = base64_decode("bGlnaHQgdw==");
   assert(output == "light w");

   printf("\n");

   TSha1Hash hash = sha1_hash(nullptr, 0);
   printf("output:\n%s\n", CPrintData::GetDataAsString((char*)&hash.Word, sizeof(hash)));

   const char* test_str = "abc";
   hash = sha1_hash((const uint8_t*)test_str, strlen(test_str));
   printf("output:\n%s\n", CPrintData::GetDataAsString((char*)&hash.Word, sizeof(hash)));

   const char* test_str1 = "a";
   hash = sha1_hash((const uint8_t*)test_str1, strlen(test_str1));
   printf("output:\n%s\n", CPrintData::GetDataAsString((char*)&hash.Word, sizeof(hash)));

   const char* test_str2 = "The quick brown fox jumps over the lazy dog";
   hash = sha1_hash((const uint8_t*)test_str2, strlen(test_str2));
   printf("output:\n%s\n", CPrintData::GetDataAsString((char*)&hash.Word, sizeof(hash)));

   const char* test_str3 = "The quick brown fox jumps over the lazy cog";
   hash = sha1_hash((const uint8_t*)test_str3, strlen(test_str3));
   printf("output:\n%s\n", CPrintData::GetDataAsString((char*)&hash.Word, sizeof(hash)));

   const char* test_str4 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
   hash = sha1_hash((const uint8_t*)test_str4, strlen(test_str4));
   printf("output:\n%s\n", CPrintData::GetDataAsString((char*)&hash.Word, sizeof(hash)));

   const char* test_str5 = "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
   hash = sha1_hash((const uint8_t*)test_str5, strlen(test_str5));
   printf("output:\n%s\n", CPrintData::GetDataAsString((char*)&hash.Word, sizeof(hash)));

   output = base64_encode((const uint8_t*)hash.Word, sizeof(hash));
   printf("output '%s'\n", output.c_str());

   const char* test_str6 = "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
   hash = sha1_hash((const uint8_t*)test_str6, strlen(test_str6));
   printf("output:\n%s\n", CPrintData::GetDataAsString((char*)&hash.Word, sizeof(hash)));
}

//   Concretely, if as in the example above, the |Sec-WebSocket-Key|
//   header field had the value "dGhlIHNhbXBsZSBub25jZQ==", the server
//   would concatenate the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
//   to form the string "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-
//   C5AB0DC85B11".  The server would then take the SHA-1 hash of this,
//   giving the value 0xb3 0x7a 0x4f 0x2c 0xc0 0x62 0x4f 0x16 0x90 0xf6
//   0x46 0x06 0xcf 0x38 0x59 0x45 0xb2 0xbe 0xc4 0xea.  This value is
//   then base64-encoded (see Section 4 of [RFC4648]), to give the value
//   "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".  This value would then be echoed in
//   the |Sec-WebSocket-Accept| header field.

//Example hashes
//These are examples of SHA-1 message digests in hexadecimal and in Base64 binary to ASCII text encoding.
//
//SHA1("The quick brown fox jumps over the lazy dog")
//Outputted hexadecimal: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
//Outputted Base64 binary to ASCII text encoding: L9ThxnotKPzthJ7hu3bnORuT6xI=
//Even a small change in the message will, with overwhelming probability, result in many bits changing due to the avalanche effect. For example, changing dog to cog produces a hash with different values for 81 of the 160 bits:
//
//SHA1("The quick brown fox jumps over the lazy cog")
//Outputted hexadecimal: de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3
//Outputted Base64 binary to ASCII text encoding: 3p8sf9JeGzr60+haC9F9mxANtLM=
//The hash of the zero-length string is:
//
//SHA1("")
//Outputted hexadecimal: da39a3ee5e6b4b0d3255bfef95601890afd80709
//Outputted Base64 binary to ASCII text encoding: 2jmj7l5rSw0yVb/vlWAYkK/YBwk=
