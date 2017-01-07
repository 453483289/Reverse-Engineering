/*
 * procdir.cpp
 *
 *  Created on: 2016Äê6ÔÂ8ÈÕ
 *      Author: lichao26
 */
#include "prodir.h"
#include <sys/types.h>
#include <dirent.h>
#include <vector>
#include <pthread.h>
#include <stdlib.h>

static pthread_mutex_t mutex;
bool init=false;
std::vector<int> dirinfo;
std::vector<int>::iterator pt;

THREAD_SAFE void ida_export qfindclose64(struct qffblk64_t *blk)
{
	printf("enter %s\n",__FUNCTION__);

	pthread_mutex_lock(&mutex);
	pt=dirinfo.begin();
	dirinfo.clear();
	pthread_mutex_unlock(&mutex);
}

#define QIsdigit(x) ((x) >= '0' && (x) <= '9')

THREAD_SAFE int qfindfirst64( const char *pattern, struct qffblk64_t *blk, int attr)
{

	memset(blk,0,sizeof(qffblk_t));
	if(!init)
		pthread_mutex_init(&mutex, NULL);

	printf("enter %s\n",__FUNCTION__);

	pthread_mutex_lock(&mutex);
	int ret = -1;


	DIR* dir = opendir("/proc");
	dirent *dir_info;
	if(dir != 0)
	{
		while((dir_info = readdir(dir)) != NULL)
		 {
			char filepath[256]="/proc/";
			strncat(filepath, dir_info->d_name, 256);
			if(!strcmp(dir_info->d_name,".") || !strcmp(dir_info->d_name,".."))
				continue;
			if(QIsdigit(dir_info->d_name[0]))
			{
				dirinfo.push_back(atoi(dir_info->d_name));
				pt = dirinfo.begin();
				printf("%s\n",dir_info->d_name);
			}
		 }
		if(dirinfo.size() != 0)
		{
			sprintf(blk->ff_name,"%d", *pt);
			pt++;
			ret = 0;
		}

		closedir(dir);
	}

	pthread_mutex_unlock(&mutex);
	return ret;
}

THREAD_SAFE int qfindnext64(struct qffblk64_t *blk)
{
//	printf("enter %s\n",__FUNCTION__);

	pthread_mutex_lock(&mutex);
	int ret = -1;


	if(dirinfo.size() > 0 && pt != dirinfo.end())
	{
		sprintf(blk->ff_name,"%d",*pt);
		pt++;

		ret = 0;
	}
	pthread_mutex_unlock(&mutex);
	return ret;
}
