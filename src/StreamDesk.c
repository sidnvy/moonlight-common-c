#include "Limelight-internal.h"
#include "StreamDesk.h"

#include <stdatomic.h>
#include <string.h>

static atomic_uint_fast32_t NextCommitMessageId = 1;
static atomic_uint_fast32_t NextClipboardEventId = 1;

static uint32_t selectUtf8ChunkLength(const char* utf8Text, uint32_t offset, uint32_t remaining) {
    uint32_t maxLen = remaining < SS_STREAM_DESK_MAX_CHUNK_BYTES ? remaining : SS_STREAM_DESK_MAX_CHUNK_BYTES;
    if (maxLen < remaining) {
        uint32_t split = maxLen;
        while (split > 0 && (((uint8_t)utf8Text[offset + split]) & 0xC0u) == 0x80u) {
            split--;
        }
        if (split > 0) {
            maxLen = split;
        }
    }
    return maxLen;
}

uint64_t LiComputeClipboardHash(const char* utf8Text, uint32_t length) {
    uint64_t hash = 14695981039346656037ULL;
    const uint64_t prime = 1099511628211ULL;

    if (utf8Text == NULL || length == 0) {
        return hash;
    }

    for (uint32_t i = 0; i < length; i++) {
        uint8_t c = (uint8_t)utf8Text[i];
        // Normalize CRLF -> LF so line-ending differences across platforms hash identically
        if (c == '\r' && (i + 1) < length && utf8Text[i + 1] == '\n') {
            continue;
        }
        hash ^= c;
        hash *= prime;
    }

    return hash;
}

int LiPackCommitTextFrame(uint32_t messageId,
                          uint16_t flags,
                          const char* chunkUtf8,
                          uint16_t chunkLength,
                          uint8_t* outBuf,
                          int outCap) {
    int totalLen = SS_COMMIT_TEXT_HEADER_SIZE + (int)chunkLength;
    if (outBuf == NULL || (chunkLength > 0 && chunkUtf8 == NULL) ||
        chunkLength > SS_STREAM_DESK_MAX_CHUNK_BYTES || outCap < totalLen) {
        return -1;
    }

    outBuf[0] = (uint8_t)((messageId >> 24) & 0xFFu);
    outBuf[1] = (uint8_t)((messageId >> 16) & 0xFFu);
    outBuf[2] = (uint8_t)((messageId >> 8) & 0xFFu);
    outBuf[3] = (uint8_t)(messageId & 0xFFu);
    outBuf[4] = (uint8_t)((flags >> 8) & 0xFFu);
    outBuf[5] = (uint8_t)(flags & 0xFFu);
    outBuf[6] = (uint8_t)((chunkLength >> 8) & 0xFFu);
    outBuf[7] = (uint8_t)(chunkLength & 0xFFu);

    if (chunkLength > 0) {
        memcpy(outBuf + SS_COMMIT_TEXT_HEADER_SIZE, chunkUtf8, chunkLength);
    }

    return totalLen;
}

bool LiUnpackCommitTextHeader(const uint8_t* packet,
                              int packetLen,
                              PSS_COMMIT_TEXT_HEADER header,
                              const char** outChunk) {
    if (packet == NULL || header == NULL || packetLen < SS_COMMIT_TEXT_HEADER_SIZE) {
        return false;
    }

    uint32_t messageId = ((uint32_t)packet[0] << 24) |
                         ((uint32_t)packet[1] << 16) |
                         ((uint32_t)packet[2] << 8) |
                         (uint32_t)packet[3];
    uint16_t flags = (uint16_t)(((uint16_t)packet[4] << 8) | (uint16_t)packet[5]);
    uint16_t payloadLength = (uint16_t)(((uint16_t)packet[6] << 8) | (uint16_t)packet[7]);

    if (payloadLength > SS_STREAM_DESK_MAX_CHUNK_BYTES ||
        packetLen < SS_COMMIT_TEXT_HEADER_SIZE + (int)payloadLength) {
        return false;
    }

    header->messageId = messageId;
    header->flags = flags;
    header->payloadLength = payloadLength;

    if (outChunk != NULL) {
        *outChunk = (const char*)(packet + SS_COMMIT_TEXT_HEADER_SIZE);
    }

    return true;
}

int LiPackClipboardEventFrame(uint32_t eventId,
                              uint64_t contentHash,
                              uint8_t origin,
                              uint8_t flags,
                              const char* chunkUtf8,
                              uint16_t chunkLength,
                              uint8_t* outBuf,
                              int outCap) {
    int totalLen = SS_CLIPBOARD_EVENT_HEADER_SIZE + (int)chunkLength;
    if (outBuf == NULL || (chunkLength > 0 && chunkUtf8 == NULL) ||
        chunkLength > SS_STREAM_DESK_MAX_CHUNK_BYTES || outCap < totalLen) {
        return -1;
    }

    outBuf[0] = (uint8_t)((eventId >> 24) & 0xFFu);
    outBuf[1] = (uint8_t)((eventId >> 16) & 0xFFu);
    outBuf[2] = (uint8_t)((eventId >> 8) & 0xFFu);
    outBuf[3] = (uint8_t)(eventId & 0xFFu);

    outBuf[4] = (uint8_t)((contentHash >> 56) & 0xFFu);
    outBuf[5] = (uint8_t)((contentHash >> 48) & 0xFFu);
    outBuf[6] = (uint8_t)((contentHash >> 40) & 0xFFu);
    outBuf[7] = (uint8_t)((contentHash >> 32) & 0xFFu);
    outBuf[8] = (uint8_t)((contentHash >> 24) & 0xFFu);
    outBuf[9] = (uint8_t)((contentHash >> 16) & 0xFFu);
    outBuf[10] = (uint8_t)((contentHash >> 8) & 0xFFu);
    outBuf[11] = (uint8_t)(contentHash & 0xFFu);

    outBuf[12] = origin;
    outBuf[13] = flags;
    outBuf[14] = (uint8_t)((chunkLength >> 8) & 0xFFu);
    outBuf[15] = (uint8_t)(chunkLength & 0xFFu);

    if (chunkLength > 0) {
        memcpy(outBuf + SS_CLIPBOARD_EVENT_HEADER_SIZE, chunkUtf8, chunkLength);
    }

    return totalLen;
}

bool LiUnpackClipboardEventHeader(const uint8_t* packet,
                                  int packetLen,
                                  PSS_CLIPBOARD_EVENT_HEADER header,
                                  const char** outChunk) {
    if (packet == NULL || header == NULL || packetLen < SS_CLIPBOARD_EVENT_HEADER_SIZE) {
        return false;
    }

    uint32_t eventId = ((uint32_t)packet[0] << 24) |
                       ((uint32_t)packet[1] << 16) |
                       ((uint32_t)packet[2] << 8) |
                       (uint32_t)packet[3];
    uint64_t contentHash = ((uint64_t)packet[4] << 56) |
                           ((uint64_t)packet[5] << 48) |
                           ((uint64_t)packet[6] << 40) |
                           ((uint64_t)packet[7] << 32) |
                           ((uint64_t)packet[8] << 24) |
                           ((uint64_t)packet[9] << 16) |
                           ((uint64_t)packet[10] << 8) |
                           (uint64_t)packet[11];
    uint8_t origin = packet[12];
    uint8_t flags = packet[13];
    uint16_t payloadLength = (uint16_t)(((uint16_t)packet[14] << 8) | (uint16_t)packet[15]);

    if (payloadLength > SS_STREAM_DESK_MAX_CHUNK_BYTES ||
        packetLen < SS_CLIPBOARD_EVENT_HEADER_SIZE + (int)payloadLength) {
        return false;
    }

    header->eventId = eventId;
    header->contentHash = contentHash;
    header->origin = origin;
    header->flags = flags;
    header->payloadLength = payloadLength;

    if (outChunk != NULL) {
        *outChunk = (const char*)(packet + SS_CLIPBOARD_EVENT_HEADER_SIZE);
    }

    return true;
}

int LiSendCommitText(const char* utf8Text, uint32_t length) {
    if ((LiGetHostFeatureFlags() & LI_FF_COMMIT_TEXT) == 0) {
        return LI_ERR_UNSUPPORTED;
    }

    if (utf8Text == NULL || length == 0 || length > LI_STREAM_DESK_MAX_TEXT_BYTES) {
        return -1;
    }

    uint32_t msgId = (uint32_t)atomic_fetch_add_explicit(&NextCommitMessageId, 1, memory_order_relaxed);
    uint8_t frame[SS_COMMIT_TEXT_HEADER_SIZE + SS_STREAM_DESK_MAX_CHUNK_BYTES];

    uint32_t offset = 0;
    while (offset < length) {
        uint32_t chunkLen = selectUtf8ChunkLength(utf8Text, offset, length - offset);
        uint16_t flags = (offset + chunkLen == length) ? SS_COMMIT_TEXT_FLAG_FINAL : 0;

        int frameLen = LiPackCommitTextFrame(msgId, flags, utf8Text + offset, (uint16_t)chunkLen, frame, (int)sizeof(frame));
        if (frameLen < 0) {
            return -1;
        }
        if (!sendCommitTextPacketOnControlStream(frame, (unsigned int)frameLen)) {
            return -1;
        }
        offset += chunkLen;
    }

    return 0;
}

int LiSendClipboardText(const char* utf8Text, uint32_t length, uint8_t flags) {
    if ((LiGetHostFeatureFlags() & LI_FF_CLIPBOARD_EVENT) == 0) {
        return LI_ERR_UNSUPPORTED;
    }

    if (utf8Text == NULL || length == 0 || length > LI_STREAM_DESK_MAX_TEXT_BYTES) {
        return -1;
    }

    uint32_t eventId = (uint32_t)atomic_fetch_add_explicit(&NextClipboardEventId, 1, memory_order_relaxed);
    uint64_t contentHash = LiComputeClipboardHash(utf8Text, length);
    uint8_t cleanFlags = (uint8_t)(flags & SS_CLIPBOARD_FLAG_SENSITIVE);
    uint8_t frame[SS_CLIPBOARD_EVENT_HEADER_SIZE + SS_STREAM_DESK_MAX_CHUNK_BYTES];

    uint32_t offset = 0;
    while (offset < length) {
        uint32_t chunkLen = selectUtf8ChunkLength(utf8Text, offset, length - offset);
        uint8_t chunkFlags = cleanFlags;
        if (offset + chunkLen == length) {
            chunkFlags |= SS_CLIPBOARD_FLAG_FINAL;
        }

        int frameLen = LiPackClipboardEventFrame(eventId,
                                                 contentHash,
                                                 SS_CLIPBOARD_ORIGIN_CLIENT,
                                                 chunkFlags,
                                                 utf8Text + offset,
                                                 (uint16_t)chunkLen,
                                                 frame,
                                                 (int)sizeof(frame));
        if (frameLen < 0) {
            return -1;
        }
        if (!sendClipboardEventPacketOnControlStream(frame, (unsigned int)frameLen)) {
            return -1;
        }
        offset += chunkLen;
    }

    return 0;
}
