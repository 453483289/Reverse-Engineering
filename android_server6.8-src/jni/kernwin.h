/*
 * kernwin.h
 *
 *  Created on: 2016Äê6ÔÂ8ÈÕ
 *      Author: lichao26
 */

#ifndef JNI_KERNWIN_H_
#define JNI_KERNWIN_H_

#define THREAD_SAFE
THREAD_SAFE uchar idaapi unpack_db(const uchar **pptr, const uchar *end);
THREAD_SAFE uint32 idaapi unpack_dd(const uchar **pptr, const uchar *end);
THREAD_SAFE uint64 idaapi unpack_dq(const uchar **pptr, const uchar *end);

THREAD_SAFE void append_db(bytevec_t &v, uchar x);
THREAD_SAFE void append_dd(bytevec_t &v, uint32 x);
THREAD_SAFE void append_dq(bytevec_t &v, uint64 x);

THREAD_SAFE char *str2user(char *dst, const char *src, size_t dstsize);
THREAD_SAFE const char *skipSpaces(const char *ptr);
inline char *skipSpaces(char *ptr) ///< \copydoc skipSpaces()
  { return CONST_CAST(char*)(skipSpaces((const char *)ptr)); }

#endif /* JNI_KERNWIN_H_ */

