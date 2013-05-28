// Copyright 2012 Cloudera Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#ifndef IMPALA_UTIL_BIT_STREAM_UTILS_INLINE_H
#define IMPALA_UTIL_BIT_STREAM_UTILS_INLINE_H

#include "util/bit-stream-utils.h"

namespace impala {

inline bool BitWriter::PutValue(uint64_t v, int num_bits) {
  DCHECK_LE(num_bits, 64);
  DCHECK(num_bits == 64 || v >> num_bits == 0)
      << "v = " << v << ", num_bits = " << num_bits;

  if (UNLIKELY(byte_offset_ * 8 + bit_offset_ + num_bits > max_bytes_ * 8)) return false;

  int bits_remaining = num_bits; // # bits left to write
  while (bits_remaining > 0) {
    buffer_[byte_offset_] |= v << bit_offset_;
    int bits_written = std::min(8 - bit_offset_, bits_remaining);
    v >>= bits_written;
    bit_offset_ += bits_written;
    byte_offset_ += bit_offset_ / 8;
    bit_offset_ %= 8;
    bits_remaining -= bits_written;
  }
  return true;
}

inline uint8_t* BitWriter::GetNextBytePtr(int num_bytes) {
  if (UNLIKELY(bit_offset_ != 0)) {
    // Advance to next aligned byte
    ++byte_offset_;
    bit_offset_ = 0;
  }
  if (byte_offset_ + num_bytes > max_bytes_) return NULL;
  uint8_t* ptr = buffer_ + byte_offset_;
  byte_offset_ += num_bytes;
  return ptr;
}

template<typename T>
inline bool BitWriter::PutAligned(T val, int num_bits) {
  // Align to byte boundary
  uint8_t* byte_ptr = GetNextBytePtr(0);
  bool result = PutValue(val, num_bits);
  if (!result) return false;
  // Pad to next byte boundary
  byte_ptr = GetNextBytePtr(0);
  DCHECK(byte_ptr != NULL);
  return true;
}

inline bool BitWriter::PutVlqInt(int32_t v) {
  bool result = true;
  while ((v & 0xFFFFFF80) != 0L) {
    result &= PutAligned<uint8_t>((v & 0x7F) | 0x80, 8);
    v >>= 7;
  }
  result &= PutAligned<uint8_t>(v & 0x7F, 8);
  return result;
}

// Returns the 'num_bits' least-significant bits of 'v'.
inline uint64_t TrailingBits(uint64_t v, int num_bits) {
  if (num_bits == 0) return 0;
  num_bits = std::min(num_bits, 64);
  int n = 64 - num_bits;
  return (v << n) >> n;
}

template<typename T>
inline bool BitReader::GetValue(int num_bits, T* v) {
  DCHECK_LE(num_bits, sizeof(T) * 8);
  if (UNLIKELY(byte_offset_ * 8 + bit_offset_ + num_bits > max_bytes_ * 8)) return false;

  *v = 0;
  int bits_remaining = num_bits; // # bits left to read
  while (bits_remaining > 0) {
    // Remove extra high-order bits via TrailingBits, remove extra low-order bits via
    // right shift, and left shift remaining bits to correct position in 'v'
    *v |= TrailingBits(buffer_[byte_offset_], bit_offset_ + bits_remaining)
          >> bit_offset_ << (num_bits - bits_remaining);
    int bits_read = std::min(8 - bit_offset_, bits_remaining);
    bit_offset_ += bits_read;
    byte_offset_ += bit_offset_ / 8;
    bit_offset_ %= 8;
    bits_remaining -= bits_read;
  }
  return true;
}

template<typename T>
inline bool BitReader::GetAligned(int num_bits, T* v) {
  Align();
  bool result = GetValue(num_bits, v);
  if (!result) return false;
  Align();
  return true;
}

inline bool BitReader::GetVlqInt(int32_t* v) {
  *v = 0;
  int shift = 0;
  int num_bytes = 0;
  uint8_t byte = 0;
  do {
    if (!GetAligned<uint8_t>(8, &byte)) return false;
    *v |= (byte & 0x7F) << shift;
    shift += 7;
    DCHECK_LE(++num_bytes, MAX_VLQ_BYTE_LEN);
  } while ((byte & 0x80) != 0);
  return true;
}

inline void BitReader::Align() {
  if (UNLIKELY(bit_offset_ != 0)) {
    ++byte_offset_;
    bit_offset_ = 0;
    DCHECK_LE(byte_offset_, max_bytes_);
  }
}

}

#endif
