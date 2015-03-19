/*
    Grapple - A fully featured network layer with a simple interface
    Copyright (C) 2006 Michael Simms

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

    Michael Simms
    michael@linuxgamepublishing.com
*/

#include "grapple_configure_substitute.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "dynstring.h"

//A set of variables for dynamically growing strings

///////////////////// chars ///////////////////////////
dynstring *dynstringInit(int datasize)
{
  dynstring *newstruct;
  
  newstruct=(dynstring *)malloc(sizeof(dynstring));
  newstruct->buf=(char *)malloc(datasize); //The actual string
  newstruct->len=0;
  newstruct->buf[0]=0;
  newstruct->maxlen=datasize;  //The maximum string length

  return newstruct;
}

//Check a length of string will fit, if it wont, grow the buffer
void dynstringCheckAvailableLength(dynstring *data,size_t length)
{
  length+=2;
  if (length+data->len > data->maxlen)
    {
      data->maxlen=length+data->len;
      data->buf=(char *)realloc(data->buf,data->maxlen);
    }
}

//Append some text to a dynstring
void dynstringAppend(dynstring *data,const char *buf)
{
  size_t length;

  if (!buf || !*buf)
    return;

  length=strlen(buf);

  //grow the buffer if required
  dynstringCheckAvailableLength(data,length);

  //Append the text
  strcpy((char *)data->buf+data->len,buf);
  data->len+=length;
  data->buf[data->len]=0;  //NULL it

  return;
}

//Append raw data to a dynstring
void dynstringRawappend(dynstring *data,const char *buf,size_t len)
{
  if (!buf)
    return;

  //Check the length
  dynstringCheckAvailableLength(data,len);

  //Set the data into the buffer
  memcpy(data->buf+data->len,buf,len);
  data->len+=len;
  data->buf[data->len]=0; //NULL it - this may not matter but its not expensive

  return;
}

//Delete a dynstring
void dynstringUninit(dynstring *data)
{
  free(data->buf);
  free(data);
  
  return;
}

///////////////////// unsigned chars ///////////////////////////
udynstring *dynstringUInit(int datasize)
{
  udynstring *newstruct;
  
  newstruct=(udynstring *)malloc(sizeof(udynstring));
  newstruct->buf=(unsigned char *)malloc(datasize); //The actual string
  newstruct->len=0;
  newstruct->buf[0]=0;
  newstruct->maxlen=datasize;  //The maximum string length

  return newstruct;
}

//Check a length of string will fit, if it wont, grow the buffer
void dynstringUCheckAvailableLength(udynstring *data,size_t length)
{
  length+=2;

  if (length+data->len > data->maxlen)
    {
      data->maxlen=length+data->len;
      data->buf=(unsigned char *)realloc(data->buf,data->maxlen);
    }
}

//Append some text to an unsigned dynstring
void dynstringUAppend(udynstring *data,const unsigned char *buf)
{
  size_t length;

  if (!buf || !*buf)
    return;

  length=strlen((const char *)buf);

  //grow the buffer if required
  dynstringUCheckAvailableLength(data,length);

  //Append the text
  strcpy((char *)data->buf+data->len,(const char *)buf);
  data->len+=length;
  data->buf[data->len]=0;  //NULL it

  return;
}

//Append raw data to an unsigned dynstring
void dynstringURawappend(udynstring *data,const unsigned char *buf,size_t len)
{
  if (!buf)
    return;

  //Check the length
  dynstringUCheckAvailableLength(data,len);

  //Set the data into the buffer
  memcpy(data->buf+data->len,buf,len);
  data->len+=len;
  data->buf[data->len]=0; //NULL it - this may not matter but its not expensive

  return;
}

//Delete an unsigned dynstring
void dynstringUUninit(udynstring *data)
{
  free(data->buf);
  free(data);
  
  return;
}

///////////////////// signed chars ///////////////////////////
sdynstring *dynstringSInit(int datasize)
{
  sdynstring *newstruct;
  
  newstruct=(sdynstring *)malloc(sizeof(sdynstring));
  newstruct->buf=(signed char *)malloc(datasize); //The actual string
  newstruct->len=0;
  newstruct->buf[0]=0;
  newstruct->maxlen=datasize;  //The maximum string length

  return newstruct;
}

//Check a length of string will fit, if it wont, grow the buffer
void dynstringSCheckAvailableLength(sdynstring *data,size_t length)
{
  length+=2;

  if (length+data->len > data->maxlen)
    {
      data->maxlen=length+data->len;
      data->buf=(signed char *)realloc(data->buf,data->maxlen);
    }
}

//Append some text to a signed dynstring
void dynstringSAppend(sdynstring *data,const signed char *buf)
{
  size_t length;

  if (!buf || !*buf)
    return;

  length=strlen((const char *)buf);

  //grow the buffer if required
  dynstringSCheckAvailableLength(data,length);

  //Append the text
  strcpy((char *)data->buf+data->len,(const char *)buf);
  data->len+=length;
  data->buf[data->len]=0;  //NULL it

  return;
}

//Append raw data to a signed dynstring
void dynstringSRawappend(sdynstring *data,const signed char *buf,size_t len)
{
  if (!buf)
    return;

  //Check the length
  dynstringSCheckAvailableLength(data,len);

  //Set the data into the buffer
  memcpy(data->buf+data->len,buf,len);
  data->len+=len;
  data->buf[data->len]=0; //NULL it - this may not matter but its not expensive

  return;
}

//Delete a signed dynstring
void dynstringSUninit(sdynstring *data)
{
  free(data->buf);
  free(data);
  
  return;
}
