/* This file was generated by statrie. DO NOT EDIT. */
#ifndef GENERIC_FALLBACKS_H
#define GENERIC_FALLBACKS_H
#include <stdint.h>
#include "transcript.h"
TRANSCRIPT_LOCAL extern const uint16_t _transcript_generic_fallbacks_data_2[122][4];
TRANSCRIPT_LOCAL extern const uint8_t _transcript_generic_fallbacks_data_1[58][8];
TRANSCRIPT_LOCAL extern const uint8_t _transcript_generic_fallbacks_data_0[37][8];
TRANSCRIPT_LOCAL extern const uint8_t _transcript_generic_fallbacks_data_idx[];
#define get_generic_fallback(x) (_transcript_generic_fallbacks_data_2[_transcript_generic_fallbacks_data_1[_transcript_generic_fallbacks_data_0[_transcript_generic_fallbacks_data_idx[(x) >> 8]][((x) >> 5) & ((1 << 3) - 1)]][((x) >> 2) & ((1 << 3) - 1)]][((x) >> 0) & ((1 << 2) - 1)])
#endif