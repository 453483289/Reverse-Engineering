/*
 * pro.cpp
 *
 *  Created on: 2016Äê6ÔÂ8ÈÕ
 *      Author: lichao26
 */

#include "pro.h"
#include "diskio.hpp"



THREAD_SAFE FILE * fopenRB(const char *file);

THREAD_SAFE void hit_counter_timer(hit_counter_t *, bool enable)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE hit_counter_t * create_hit_counter(const char *name)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE bool relocate_relobj(struct relobj_t *_relobj, ea_t ea, bool mf)
{
	printf("not implement %s\n",__FUNCTION__);
}


THREAD_SAFE char * qstrncpy(char *dst, const char *src, size_t dstsize)
{
	return strncpy(dst, src, dstsize);
}

THREAD_SAFE char *qstpncpy(char *dst, const char *src, size_t dstsize)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE char * qstrdup(const char *string)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE bool qisabspath(const char *file)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE char * qmake_full_path(char *dst, size_t dstsize, const char *src)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE void qatexit(void (idaapi *func)(void))
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE void del_qatexit(void (idaapi*func)(void))
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE NORETURN void qexit(int code)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE bool qfileexist(const char *file)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE int qstat64(const char *path, qstatbuf64 *buf)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE const char * stristr(const char *s1, const char *s2)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE const char * qbasename(const char *path)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE void *qalloc_or_throw(size_t size)
{
	if(size == 0)
		throw "bad allocation";
	return malloc(size);
}
THREAD_SAFE int  qwait_timed(int child, int *status, int flags, int timeout_ms)
{
	return 0;
}

THREAD_SAFE void *launch_process(const launch_process_params_t &lpp, qstring *errbuf)
{
	printf("not implement %s\n",__FUNCTION__);
}



linput_t* open_linput(const char* path, bool remote)
{
	static linput_t pool[16]={0};
	if(!remote)
	{
		for(int i=0;i<16;i++)
		{
			if(pool[0].contype != 0)
			{
				pool[i].contype = remote?2:1;
				pool[i].file = fopenRB(path);
				return &pool[i];
			}
		}
		return 0;
	}
	else
	{
		printf("not implement %s\n",__FUNCTION__);
		return 0;
	}
}

void close_linput(linput_t* input)
{
	if(!input)
		return;
	if(input->contype < 2)
	{
		fclose(input->file);
		input->contype = 0;
	}
	else
	{
		printf("not implement %s\n",__FUNCTION__);
	}
}

int32 calc_file_crc32(linput_t* input)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE void get_nsec_stamp(uint64 *nsecs)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE int call_system(const char *command)
{
	printf("not implement %s\n",__FUNCTION__);
}

THREAD_SAFE const char *skipSpaces(const char *ptr)
{
	char* tmp = (char*)ptr;
	while(isspace(*tmp))
		tmp++;
	return (const char*)tmp;
}
