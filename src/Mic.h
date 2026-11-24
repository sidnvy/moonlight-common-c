#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SS_MIC_OPUS_PTYPE 0x5510

#pragma pack(push, 1)
typedef struct _SS_MIC_FRAME_HEADER {
    uint16_t sequenceNumber;   // Big-endian
    uint16_t opusFrameLength;  // Big-endian
    uint32_t timestampSamples; // Big-endian, independent monotonic sample counter
} SS_MIC_FRAME_HEADER, *PSS_MIC_FRAME_HEADER;
#pragma pack(pop)

// Packs one Opus microphone frame into outBuffer with SS_MIC_FRAME_HEADER.
// Returns total packed byte length on success, or -1 on invalid arguments.
int LiPackMicAudioFrame(const unsigned char* opusData,
                        int opusLength,
                        uint16_t seqNumber,
                        uint32_t timestampSamples,
                        unsigned char* outBuffer,
                        int outBufferSize);

#ifdef __cplusplus
}
#endif
