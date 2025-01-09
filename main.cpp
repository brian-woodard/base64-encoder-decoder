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
      value = (value >> 8) << (6 - num_bits);
      assert(value >= 0 && value < 64);
      output += encode_char[value];
   }

   return output;
}

int main()
{
   printf("Test 'Man' encode\n");
   std::string output = base64_encode("Man");
   assert(output == "TWFu");

   printf("Test 'Many hands make light work.' encode\n");
   output = base64_encode("Many hands make light work.");
   assert(output == "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu");

   printf("Test 'light wor' encode\n");
   output = base64_encode("light wor");
   assert(output == "bGlnaHQgd29y");
}
