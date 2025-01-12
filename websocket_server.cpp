#include <iostream>
#include <sstream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <cstdint>
#include <algorithm>
#include <cstring>
#include <cassert>
#include <climits>
#include "PrintData.h"
#include "IosDataTypes.h"

// Example handshake request from client:
// ----------------------------------------------------------
// GET /chat HTTP/1.1
// Host: server.example.com
// Upgrade: websocket
// Connection: Upgrade
// Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
// Origin: http://example.com
// Sec-WebSocket-Protocol: chat, superchat
// Sec-WebSocket-Version: 13

// Example handshake response from server:
// ----------------------------------------------------------
// HTTP/1.1 101 Switching Protocols
// Upgrade: websocket
// Connection: Upgrade
// Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
// Sec-WebSocket-Protocol: chat

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

const char* WEB_SOCKET_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

int main()
{
   std::string protocol;
   std::string key;
   int         server = socket(AF_INET, SOCK_STREAM, 0);
   int         client = -1;
   bool        handshake = true;

   struct sockaddr_in server_addr;
   server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
   server_addr.sin_family = AF_INET;
   server_addr.sin_port = htons(4000);

   bind(server, (struct sockaddr *)&server_addr, sizeof(server_addr));
   listen(server, 5);

   while (1)
   {
      //printf("Client %d, handshake = %d\n", client, handshake);

      if (client == -1)
      {
         // Blocks?
         client = accept(server, nullptr, nullptr);
      }
      else
      {
         uint8_t buffer[1024];
         int bytes = recv(client, buffer, sizeof(buffer), 0);

         if (bytes > 0 && handshake)
         {
            bool websocket_request = false;

            printf("Received %d bytes from client\n", bytes);
            printf("%s\n", CPrintData::GetDataAsString((char*)buffer, bytes));

            // parse message, only handle web socket requests
            std::stringstream buffer_stream;
            std::string       line;

            protocol = "";
            key = "";

            buffer_stream << buffer;
            while (std::getline(buffer_stream, line))
            {
               if (line.find("Sec-WebSocket-Protocol") != std::string::npos)
               {
                  std::stringstream tokenize(line);

                  std::getline(tokenize, protocol, ':');
                  std::getline(tokenize, protocol, ':');

                  // remove whitespace
                  protocol.erase(std::remove_if(protocol.begin(), protocol.end(), isspace), protocol.end());
                  websocket_request = true;
               }
               else if (line.find("Sec-WebSocket-Key") != std::string::npos)
               {
                  std::stringstream tokenize(line);
                  std::getline(tokenize, key, ':');
                  std::getline(tokenize, key, ':');

                  // remove whitespace
                  key.erase(std::remove_if(key.begin(), key.end(), isspace), key.end());
               }
            }

            if (websocket_request)
            {
               handshake = false;

               std::string key_response = key + WEB_SOCKET_MAGIC;
               TSha1Hash hash = sha1_hash((const uint8_t*)key_response.data(), key_response.length());
               key_response = base64_encode((const uint8_t*)hash.Word, sizeof(hash));

               std::string handshake_response;

               handshake_response  = "HTTP/1.1 101 Switching Protocols\r\n";
               handshake_response += "Upgrade: websocket\r\n";
               handshake_response += "Connection: upgrade\r\n";
               handshake_response += "Sec-WebSocket-Accept: " + key_response + "\r\n";
               handshake_response += "Sec-WebSocket-Protocol: " + protocol + "\r\n\r\n";

               int bytes = send(client, handshake_response.data(), handshake_response.length(), 0);
               printf("Responded with %d bytes\n", bytes);
            }
            else
            {
               // Not a websocket client, close this connection
               close(client);
               client = -1;
            }
         }
         else if (bytes > 0 && !handshake)
         {
            int fin_bit = buffer[0] & 0x80;
            int opcode = buffer[0] & 0xf;
            int mask_bit = buffer[1] & 0x80;
            int length = buffer[1] & 0x7f;

            // Length of the payload (extension data + application data) in bytes.
            // 0–125 = This is the payload length.
            // 126 = The following 16 bits are the payload length.
            // 127 = The following 64 bits (MSB must be 0) are the payload length.
            // 
            // Endianness is big-endian. Signedness is unsigned.
            // The minimum number of bits must be used to encode the length.

            printf("\nReceived %d bytes from client\n", bytes);
            printf("%s\n", CPrintData::GetDataAsString((char*)buffer, bytes));

            // only support unfragmented binary messages, messages from client
            // must be masked
            assert(fin_bit != 0);
            assert(opcode == 2);
            assert(mask_bit != 0);

            uint8_t mask[4] = { buffer[2], buffer[3], buffer[4], buffer[5] };

            // unmask the payload data
            for (int i = 0; i < length; i++)
            {
               buffer[i + 6] = buffer[i + 6] ^ mask[i % 4];
            }

            if (length == sizeof(TSyncRequestMessage))
            {
               TSyncRequestMessage* sync_request = (TSyncRequestMessage*)&buffer[6];
               printf("MsgId: %d\n", sync_request->Header.MsgId);
               printf("Size:  %d\n", sync_request->Header.Size);

               char output_buffer[USHRT_MAX];
               int  offset = 0;

               TSyncResponseMessage msg;

               msg.Header.MsgId = TMessageType::SYNC_RESPONSE;
               msg.Header.Size = sizeof(msg);
               msg.ServerSendPort = 35000;
               msg.ServerReceivePort = 35000;

               // Build output buffer (add on 2-byte header, no masking)
               output_buffer[offset++] = 0x82; // set FIN and opcode to 2 (binary)

               // Length of the payload (extension data + application data) in bytes.
               // 0–125 = This is the payload length.
               // 126 = The following 16 bits are the payload length.
               // 127 = The following 64 bits (MSB must be 0) are the payload length.
               //  
               // Endianness is big-endian. Signedness is unsigned.
               // The minimum number of bits must be used to encode the length.
               if (msg.Header.Size <= 125)
               {   
                  output_buffer[offset++] = msg.Header.Size;
               }   
               else if (msg.Header.Size < (USHRT_MAX - 4)) 
               {   
                  uint16_t length = msg.Header.Size;

                  output_buffer[offset++] = 126;

                  memcpy(&output_buffer[offset], &length, sizeof(length));
                  offset += sizeof(length);
               }   
               else
               {   
                  return -1; 
               }   

               memcpy(&output_buffer[offset], (const char*)&msg, sizeof(msg));

               int bytes = send(client, output_buffer, sizeof(msg) + offset, 0);
               printf("\nResponded with %d bytes\n", bytes);
               printf("%s\n", CPrintData::GetDataAsString(output_buffer, bytes));
            }
         }
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(100));
   }
}
