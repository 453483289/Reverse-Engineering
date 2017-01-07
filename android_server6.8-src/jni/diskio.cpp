/*
 * diskio.cpp
 *
 *  Created on: 2016Äê6ÔÂ8ÈÕ
 *      Author: lichao26
 */

#include "diskio.hpp"
#include <stdio.h>

THREAD_SAFE FILE * fopenRT(const char *file)
{
	return fopen(file, "r");
}

THREAD_SAFE FILE * fopenRB(const char *file)
{
	return fopen(file, "rb");
}

THREAD_SAFE FILE * fopenWB(const char *file)
{
	return fopen(file, "wb");
}

ssize_t qlread(linput_t *li, void *buf, size_t size)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE uint32 qfsize(FILE *fp)
{
	long origin = ftell(fp);
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	fseek(fp, origin, SEEK_SET);
	return size;
}

int64 qlsize64(linput_t *li)
{
	if(!li)
		return -1;
	if(li->contype < 2)
		return qfsize(li->file);
	else
		return li->size;
}


qoff64_t qlseek64(linput_t *li, qoff64_t pos, int whence)
{
	printf("not implement %s\n",__FUNCTION__);
}

int lreadbytes(linput_t *li, void *buf, size_t size, bool mf)
{
	printf("not implement %s\n",__FUNCTION__);
}
