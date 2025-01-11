///////////////////////////////////////////////////////////////////////////////
// 
// File: IosDataTypes.h
// Date:
// Revision:
// Creator: Jason Stinnett
// License: (C) Copyright 2024 by Everus Engineering LLC. All Rights Reserved.
//
// IOS Data Types
//
///////////////////////////////////////////////////////////////////////////////
#pragma once
#include <cstdint>
#include <cstring>

// Ensure structures are packed with 1-byte alignment
#pragma pack(push, 1)

// Maximum size for the data buffer in messages
const size_t MAX_DATA_SIZE = 1024;

// Enumeration of message types
enum class TMessageType : uint16_t
{
   SYNC_REQUEST = 1,   // Initial sync request
   SYNC_RESPONSE = 2,  // Server sync response
   HEARTBEAT = 3,      // Heartbeat message
   OTHER = 99          // Placeholder for other message types
};

// Base structure for all messages
struct TIosMessageHeader
{
   TMessageType MsgId;   // Message type
   uint16_t Size;       // Total size of the message (header + data)
};

// Heartbeat message (only contains the header)
struct THeartbeatMessage
{
   TIosMessageHeader Header; // Message header
};

// Sync request message (only contains the header)
struct TSyncRequestMessage
{
   TIosMessageHeader Header; // Message header
};

// Sync response message (server to client)
struct TSyncResponseMessage
{
   TIosMessageHeader Header; // Message header
   uint16_t ServerSendPort;    // Port the server uses to send messages
   uint16_t ServerReceivePort; // Port the server listens on for the client
};

// General message with raw data (for other message types)
struct TGeneralMessage
{
   TIosMessageHeader Header;       // Message header
   uint8_t Data[MAX_DATA_SIZE];   // Raw data buffer
};

// Restore default alignment
#pragma pack(pop)


