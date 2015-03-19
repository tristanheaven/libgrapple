#ifndef TEST_H
#define TEST_H

#include <sys/time.h>
#include <time.h>

typedef struct
{
  char *name;
  char *serveraddr;
  int serverport;
  int iamserver;
  char indata[1024];
} basedata;

typedef struct 
{
  int id;
  int score;
  struct timeval answerat;
  char answer;
} serveruser;

typedef struct 
{
  char *name;
  int id;
  int me;
  int score;
} clientuser;

typedef union
{
  int i;
  char c[4];
} intchar;


#endif
