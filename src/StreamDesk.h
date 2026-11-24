#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Control-stream packet types for Stream-Desk productivity extensions (encrypted ENet control stream)
#define SS_COMMIT_TEXT_PTYPE     0x5511
#define SS_CLIPBOARD_EVENT_PTYPE 0x5512

#define SS_STREAM_DESK_MAX_CHUNK_BYTES 16384

#define SS_COMMIT_TEXT_FLAG_FINAL 0x0001

#define SS_CLIPBOARD_FLAG_FINAL     0x01
#define SS_CLIPBOARD_FLAG_SENSITIVE 0x02

#define SS_CLIPBOARD_ORIGIN_HOST   0x01
#define SS_CLIPBOARD_ORIGIN_CLIENT 0x02

#define SS_COMMIT_TEXT_HEADER_SIZE     8
#define SS_CLIPBOARD_EVENT_HEADER_SIZE 16

typedef struct _SS_COMMIT_TEXT_HEADER {
    uint32_t messageId;
    uint16_t flags;
    uint16_t payloadLength;
} SS_COMMIT_TEXT_HEADER, *PSS_COMMIT_TEXT_HEADER;

typedef struct _SS_CLIPBOARD_EVENT_HEADER {
    uint32_t eventId;
    uint64_t contentHash;
    uint8_t origin;
    uint8_t flags;
    uint16_t payloadLength;
} SS_CLIPBOARD_EVENT_HEADER, *PSS_CLIPBOARD_EVENT_HEADER;

int LiPackCommitTextFrame(uint32_t messageId,
                          uint16_t flags,
                          const char* chunkUtf8,
                          uint16_t chunkLength,
                          uint8_t* outBuf,
                          int outCap);

bool LiUnpackCommitTextHeader(const uint8_t* packet,
                              int packetLen,
                              PSS_COMMIT_TEXT_HEADER header,
                              const char** outChunk);

int LiPackClipboardEventFrame(uint32_t eventId,
                              uint64_t contentHash,
                              uint8_t origin,
                              uint8_t flags,
                              const char* chunkUtf8,
                              uint16_t chunkLength,
                              uint8_t* outBuf,
                              int outCap);

bool LiUnpackClipboardEventHeader(const uint8_t* packet,
                                  int packetLen,
                                  PSS_CLIPBOARD_EVENT_HEADER header,
                                  const char** outChunk);

#ifdef __cplusplus
}
#endif
