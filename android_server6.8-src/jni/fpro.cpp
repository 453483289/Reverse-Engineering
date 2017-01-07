/*
 * fpro.cpp
 *
 *  Created on: 2016Äê6ÔÂ8ÈÕ
 *      Author: lichao26
 */

#include "fpro.h"


THREAD_SAFE NORETURN void interr(int code)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE int qvprintf(const char *format, va_list va)
{
	vprintf(format, va);
}

THREAD_SAFE int qveprintf(const char *format, va_list va)
{
	vprintf(format, va);
}


THREAD_SAFE error_t set_qerrno(error_t code)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE void * qalloc(size_t size)
{
	return malloc(size);
}

THREAD_SAFE void * qrealloc(void *alloc, size_t newsize)
{
	return realloc(alloc, newsize);
}

THREAD_SAFE void qfree(void *alloc)
{
	free(alloc);
}

THREAD_SAFE void * qvector_reserve(void *vec, void *old, size_t cnt, size_t elsize)
{
	  unsigned int v4; // ebp@1
	  unsigned int v5; // esi@1
	  size_t v6; // edi@3
	  void* result; // eax@11
	  char v8; // [sp+10h] [bp-Ch]@12
	  v4 = 2 * *((unsigned int *)vec + 2);
	  v5 = v4;
	  if ( v4 <= cnt )
	    v5 = cnt;
	  v6 = -1;
	  if ( elsize && v5 && v5 > 0xFFFFFFFF / elsize )
	  {
	    if ( cnt < v4 && (!cnt || cnt <= 0xFFFFFFFF / elsize) )
	    {
	      v5 = cnt;
	      v6 = elsize * cnt;
	    }
	  }
	  else
	  {
	    v6 = elsize * v5;
	  }
	  result = qrealloc(old, v6);
	  *((unsigned int *)vec + 2) = v5;
	  return result;
}

THREAD_SAFE FILE * qfopen(const char *file, const char *mode)
{
	return fopen(file, mode);
}

THREAD_SAFE int qsnprintf(char *buffer, size_t n, const char *format, ...)
{
	va_list args;
	va_start(args,format);
	return vsprintf(buffer, format, args);
}

THREAD_SAFE int  qvsnprintf(char *buffer, size_t n, const char *format, va_list va)
{
	return vsnprintf(buffer, n, format, va);
}

THREAD_SAFE int qsscanf(const char *input, const char *format, ...)
{
	va_list args;
	va_start(args,format);
	return vsscanf(input, format, args);
}

THREAD_SAFE char *qfgets(char *s, size_t len, FILE *fp)
{
	return fgets(s, len, fp);
}

THREAD_SAFE int qfread(FILE *fp, void *buf, size_t n)
{
	return fread(buf, n, 1, fp);
}

THREAD_SAFE int qfseek(FILE *fp, int32 offset, int whence)
{
	return fseek(fp, offset, whence);
}

THREAD_SAFE int qfwrite(FILE *fp, const void *buf, size_t n)
{
	return fwrite(buf, n, 1, fp);
}

THREAD_SAFE int qfclose(FILE *fp)
{
	return fclose(fp);
}



bool under_debugger = false;
