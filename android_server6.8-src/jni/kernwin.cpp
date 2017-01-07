/*
 * kernwin.cpp
 *
 *  Created on: 2016Äê6ÔÂ8ÈÕ
 *      Author: lichao26
 */

#ifndef JNI_KERNWIN_CPP_
#define JNI_KERNWIN_CPP_

#include "pro.h"

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;
#define HIWORD(I) ( ( WORD ) ( ( ( DWORD )( I ) >> 16) & 0xFFFF ) )
#define HIBYTE(I) ((BYTE)((DWORD)(I) >> 8))

uchar *put_dw(uchar *a1, const uchar *a2, ushort a3)
{
  const uchar *v3; // ecx@1
  uchar *result; // eax@1

  v3 = a2;
  result = a1;
  if ( a2 - a1 < 0 )
  {
	  printf("error\n");
  }
  if ( result < v3 )
  {
    *result++ = HIBYTE(a3);
    if ( result < v3 )
      *result++ = a3;
  }
  return result;
}

THREAD_SAFE uchar * pack_dd(uchar *ptr, uchar *end, uint32 x)
{

	  uchar *result; // eax@1
	  uchar *v4; // eax@11

	  result = ptr;
	  if ( end - ptr < 0 )
	  {
	    printf("error\n");
	  }
	  if ( x > 0x7F )
	  {
	    if ( x > 0x3FFF )
	    {
	      if ( x > 0x1FFFFFFF )
	      {
	        *result = -1;
	        v4 = put_dw(result + 1, end, HIWORD(x));
	      }
	      else
	      {
	        v4 = put_dw(result, end, HIWORD(x) | 0xC000);
	      }
	      result = put_dw(v4, end, x);
	    }
	    else
	    {
	      result = put_dw(result, end, x | 0x8000);
	    }
	  }
	  else if ( result < end )
	  {
	    *result++ = x;
	  }
	  return result;
}

THREAD_SAFE uchar * pack_dq(uchar *ptr, uchar *end, uint64 x)
{
#define HIDWORD(x) (uint32)(x >> 32)
	return pack_dd(pack_dd(ptr, end, (uint32)x), end, HIDWORD(x));
}

THREAD_SAFE uchar idaapi unpack_db(const uchar **pptr, const uchar *end)
{
  const uchar *ptr = *pptr;
  uchar x = 0;
  if ( ptr < end )
    x = *ptr++;
  *pptr = ptr;
  return x;
}

ushort get_dw(const uchar **a1, const uchar *a2)
{
  const uchar *v2; // ecx@1
  ushort v3; // si@2
  const uchar *v4; // ecx@2
  ushort result; // ax@2

  v2 = *a1;
  if ( *a1 >= a2 )
  {
    *a1 = v2;
    result = 0;
  }
  else
  {
    v3 = *v2 << 8;
    v4 = v2 + 1;
    result = v3;
    if ( v4 < a2 )
      result = *v4++ | v3;
    *a1 = v4;
  }
  return result;
}

THREAD_SAFE uint32 idaapi unpack_dd(const uchar **pptr, const uchar *end)
{
	  const uchar **v2; // ebp@1
	  uchar *v3; // ecx@1
	  const uchar *v4; // edi@1
	  uint32 result; // eax@1
	  ushort v6; // si@6
	  ushort v7; // ax@6

	  v2 = pptr;
	  v3 = (uchar *)*pptr;
	  v4 = end;
	  result = 0;
	  pptr = (const uchar **)v3;
	  if ( v3 < end )
	  {
	    result = *v3++;
	    pptr = (const uchar **)v3;
	  }
	  if ( (result & 0x80u) == 0 )
	    goto LABEL_14;
	  if ( (result & 0xC0) != -64 )
	  {
	    if ( v3 < end )
	      result = *v3++ + ((result & 0xFFFFFF7F) << 8);
	LABEL_14:
	    *v2 = v3;
	    return result;
	  }
	  if ( (result & 0xE0) == -32 )
	  {
	    v6 = get_dw((const uchar **)&pptr, end);
	    v7 = get_dw((const uchar **)&pptr, v4);
	  }
	  else
	  {
	    if ( v3 >= end )
	    {
	      v6 = 0;
	    }
	    else
	    {
	      v6 = *v3 + ((result & 0x3F) << 8);
	      pptr = (const uchar **)(v3 + 1);
	    }
	    v7 = get_dw((const uchar **)&pptr, end);
	  }
	  *v2 = (const uchar *)pptr;
	  return v7 + (v6 << 16);
}

THREAD_SAFE uint64 idaapi unpack_dq(const uchar **pptr, const uchar *end)
{
#define MAKEQWORD(x,y) (uint64)(((uint32)x << 32) | ((uint32)y))
	uint32 tmp = unpack_dd(pptr, end);
	return MAKEQWORD(unpack_dd(pptr, end), tmp);
}


/// Append 'size' bytes from 'obj' to the bytevec;

THREAD_SAFE inline void append_obj(bytevec_t &v, const void *obj, size_t size)
{
  v.append(obj, size);
}

THREAD_SAFE void append_db(bytevec_t &v, uchar x)
{
	printf("not implement %s\n",__FUNCTION__);
}

/// Pack a double word and append the result to the bytevec

THREAD_SAFE void append_dd(bytevec_t &v, uint32 x)
{
  uchar packed[5];
  size_t len = pack_dd(packed, packed+sizeof(packed), x) - packed;
  append_obj(v, packed, len);
}

/// Pack a quadword and append the result to the bytevec

THREAD_SAFE void append_dq(bytevec_t &v, uint64 x)
{
  uchar packed[10];
  size_t len = pack_dq(packed, packed+sizeof(packed), x) - packed;
  append_obj(v, packed, len);
}






THREAD_SAFE char *str2user(char *dst, const char *src, size_t dstsize)
{
	printf("not implement %s\n",__FUNCTION__);
}






#endif /* JNI_KERNWIN_CPP_ */
