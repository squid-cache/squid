// Copyright 2016 Google Inc. All Rights Reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the COPYING file in the root of the source
// tree. An additional intellectual property rights grant can be found
// in the file PATENTS. All contributing project authors may
// be found in the AUTHORS file in the root of the source tree.
// -----------------------------------------------------------------------------
//
//  Utility functions used by the image decoders.
//

#include "./imageio_util.h"
#include "./image_dec.h"
#include "webp/encode.h"

#if defined(_WIN32)
#include <fcntl.h>   // for _O_BINARY
#include <io.h>      // for _setmode()
#endif
#include <stdlib.h>
#include <string.h>

// -----------------------------------------------------------------------------
// File I/O

FILE* ImgIoUtilSetBinaryMode(FILE* file) {
#if defined(_WIN32)
  if (_setmode(_fileno(file), _O_BINARY) == -1) {
    fprintf(stderr, "Failed to reopen file in O_BINARY mode.\n");
    return NULL;
  }
#endif
  return file;
}

int ImgIoUtilReadFromStdin(const uint8_t** data, size_t* data_size) {
  static const size_t kBlockSize = 16384;  // default initial size
  size_t max_size = 0;
  size_t size = 0;
  uint8_t* input = NULL;

  if (data == NULL || data_size == NULL) return 0;
  *data = NULL;
  *data_size = 0;

  if (!ImgIoUtilSetBinaryMode(stdin)) return 0;

  while (!feof(stdin)) {
    // We double the buffer size each time and read as much as possible.
    const size_t extra_size = (max_size == 0) ? kBlockSize : max_size;
    void* const new_data = realloc(input, max_size + extra_size);
    if (new_data == NULL) goto Error;
    input = (uint8_t*)new_data;
    max_size += extra_size;
    size += fread(input + size, 1, extra_size, stdin);
    if (size < max_size) break;
  }
  if (ferror(stdin)) goto Error;
  *data = input;
  *data_size = size;
  return 1;

 Error:
  free(input);
  fprintf(stderr, "Could not read from stdin\n");
  return 0;
}

int ImgIoUtilReadFile(const char* const file_name,
                      const uint8_t** data, size_t* data_size) {
  int ok;
  void* file_data;
  size_t file_size;
  FILE* in;
  const int from_stdin = (file_name == NULL) || !strcmp(file_name, "-");

  if (from_stdin) return ImgIoUtilReadFromStdin(data, data_size);

  if (data == NULL || data_size == NULL) return 0;
  *data = NULL;
  *data_size = 0;

  in = fopen(file_name, "rb");
  if (in == NULL) {
    fprintf(stderr, "cannot open input file '%s'\n", file_name);
    return 0;
  }
  fseek(in, 0, SEEK_END);
  file_size = ftell(in);
  fseek(in, 0, SEEK_SET);
  file_data = malloc(file_size);
  if (file_data == NULL) return 0;
  ok = (fread(file_data, file_size, 1, in) == 1);
  fclose(in);

  if (!ok) {
    fprintf(stderr, "Could not read %d bytes of data from file %s\n",
            (int)file_size, file_name);
    free(file_data);
    return 0;
  }
  *data = (uint8_t*)file_data;
  *data_size = file_size;
  return 1;
}

int ImgIoUtilWriteFile(const char* const file_name,
                       const uint8_t* data, size_t data_size) {
  int ok;
  FILE* out;
  const int to_stdout = (file_name == NULL) || !strcmp(file_name, "-");

  if (data == NULL) {
    return 0;
  }
  out = to_stdout ? ImgIoUtilSetBinaryMode(stdout) : fopen(file_name, "wb");
  if (out == NULL) {
    fprintf(stderr, "Error! Cannot open output file '%s'\n", file_name);
    return 0;
  }
  ok = (fwrite(data, data_size, 1, out) == 1);
  if (out != stdout) fclose(out);
  return ok;
}

// -----------------------------------------------------------------------------

void ImgIoUtilCopyPlane(const uint8_t* src, int src_stride,
                        uint8_t* dst, int dst_stride, int width, int height) {
  while (height-- > 0) {
    memcpy(dst, src, width * sizeof(*dst));
    src += src_stride;
    dst += dst_stride;
  }
}

// -----------------------------------------------------------------------------

int ImgIoUtilCheckSizeArgumentsOverflow(uint64_t nmemb, size_t size) {
  const uint64_t total_size = nmemb * size;
  int ok = (total_size == (size_t)total_size);
#if defined(WEBP_MAX_IMAGE_SIZE)
  ok = ok && (total_size <= (uint64_t)WEBP_MAX_IMAGE_SIZE);
#endif
  return ok;
}

int TryTranscodingImage(const uint8_t* data, int len, void** encoded_data, size_t* encoded_len) {
    int ok = 0;
    WebPPicture picture;
    WebPConfig config;
    WebPMemoryWriter memory_writer;

    WebPMemoryWriterInit(&memory_writer);
    if (!WebPPictureInit(&picture) || !WebPConfigInit(&config))
        return 0;

    WebPImageReader reader = WebPGuessImageReader(data, len);
    ok = reader(data, len, &picture, /*keep_alpha*/ 1, NULL /* metadata */);
    if (!ok)
        return 0;

    picture.writer = WebPMemoryWrite;
    picture.custom_ptr = (void*)&memory_writer;
    if (!WebPEncode(&config, &picture))
        return 0;

    //WebPMemoryWriterClear(&memory_writer);
    free(picture.extra_info);
    WebPPictureFree(&picture);
    *encoded_data = memory_writer.mem;
    *encoded_len = memory_writer.size;
    return 1;
}
// -----------------------------------------------------------------------------
