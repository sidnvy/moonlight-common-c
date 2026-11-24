#include "Limelight-internal.h"
#include "Mic.h"

#include <string.h>

static void writeBe16(unsigned char* dst, uint16_t val) {
    dst[0] = (unsigned char)((val >> 8) & 0xFF);
    dst[1] = (unsigned char)(val & 0xFF);
}

static void writeBe32(unsigned char* dst, uint32_t val) {
    dst[0] = (unsigned char)((val >> 24) & 0xFF);
    dst[1] = (unsigned char)((val >> 16) & 0xFF);
    dst[2] = (unsigned char)((val >> 8) & 0xFF);
    dst[3] = (unsigned char)(val & 0xFF);
}

int LiPackMicAudioFrame(const unsigned char* opusData,
                        int opusLength,
                        uint16_t seqNumber,
                        uint32_t timestampSamples,
                        unsigned char* outBuffer,
                        int outBufferSize) {
    int totalLength;

    if (opusData == NULL || outBuffer == NULL ||
        opusLength <= 0 || opusLength > LI_MIC_MAX_OPUS_BYTES) {
        return -1;
    }

    totalLength = (int)sizeof(SS_MIC_FRAME_HEADER) + opusLength;
    if (outBufferSize < totalLength) {
        return -1;
    }

    writeBe16(outBuffer + 0, seqNumber);
    writeBe16(outBuffer + 2, (uint16_t)opusLength);
    writeBe32(outBuffer + 4, timestampSamples);
    memcpy(outBuffer + sizeof(SS_MIC_FRAME_HEADER), opusData, (size_t)opusLength);
    return totalLength;
}

int LiSendMicAudioFrame(const unsigned char* opusData,
                        int opusLength,
                        uint16_t seqNumber,
                        uint32_t timestampSamples) {
    unsigned char buffer[sizeof(SS_MIC_FRAME_HEADER) + LI_MIC_MAX_OPUS_BYTES];
    int packedLen;

    if (!(SunshineFeatureFlags & LI_FF_MIC_INPUT)) {
        return LI_ERR_UNSUPPORTED;
    }

    packedLen = LiPackMicAudioFrame(opusData, opusLength, seqNumber, timestampSamples,
                                    buffer, (int)sizeof(buffer));
    if (packedLen < 0) {
        return -1;
    }

    return sendMicPacketOnControlStream(buffer, packedLen);
}
