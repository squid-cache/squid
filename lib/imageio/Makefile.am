## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

include $(top_srcdir)/src/Common.am

noinst_LIBRARIES = libimageio.a

noinst_HEADERS = image_dec.h image_enc.h imageio_util.h jpegdec.h metadata.h pngdec.h pnmdec.h tiffdec.h webpdec.h wicdec.h

libimageio_a_SOURCES = image_dec.h image_enc.h imageio_util.h jpegdec.h metadata.h pngdec.h pnmdec.h tiffdec.h webpdec.h wicdec.h image_dec.c image_enc.c imageio_util.c jpegdec.c metadata.c pngdec.c pnmdec.c tiffdec.c webpdec.c wicdec.c 

libimageio_a_CPPFLAGS = $(PNG_INCLUDES) $(JPEG_INCLUDES)
