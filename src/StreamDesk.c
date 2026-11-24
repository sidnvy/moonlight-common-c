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
    return LiStreamDeskComputeClipboardHash(utf8Text, length);
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
    uint64_t contentHash = LiStreamDeskComputeClipboardHash(utf8Text, length);
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
