#include <iostream>
#include <cstdint>
#include <cassert>

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

std::string base64_encode(const std::string& Input)
{
   std::string output = "";

   if (Input.empty())
      return output;

   uint16_t value = 0;
   uint16_t num_bits = 0;

   for (const auto& c : Input)
   {
      // Get input character
      value = (value & 0xff00) + c;
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
      value = ((value << 6) & 0xffc0) + (decode_from_char[c] & 0x003f);
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
   printf("Test 'Man' encode\n");
   std::string output = base64_encode("Man");
   assert(output == "TWFu");

   printf("Test 'Many hands make light work.' encode\n");
   output = base64_encode("Many hands make light work.");
   assert(output == "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu");

   printf("Test 'light work.' encode\n");
   output = base64_encode("light work.");
   assert(output == "bGlnaHQgd29yay4=");

   printf("Test 'light work' encode\n");
   output = base64_encode("light work");
   assert(output == "bGlnaHQgd29yaw==");

   printf("Test 'light wor' encode\n");
   output = base64_encode("light wor");
   assert(output == "bGlnaHQgd29y");

   printf("Test 'light wo' encode\n");
   output = base64_encode("light wo");
   assert(output == "bGlnaHQgd28=");

   printf("Test 'light w' encode\n");
   output = base64_encode("light w");
   assert(output == "bGlnaHQgdw==");

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
}
