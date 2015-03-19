/*
 * UFC-crypt: ultra fast crypt(3) implementation
 *
 * Copyright (C) 1991, Michael Glad, email: glad@daimi.aau.dk
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * @(#)crypt.c	2.2 10/04/91
 *
 * Semiportable C version
 *
 */

#ifndef _UFC_CRYPT_UTIL_H
#define _UFC_CRYPT_UTIL_H	1

extern void setup_salt(const char *);
extern void mk_keytab(const char *);
extern void pr_bits();
extern char *output_conversion(unsigned long,unsigned long,unsigned long,
			       unsigned long,const char *);

extern unsigned long sb0[], sb1[], sb2[], sb3[];
extern unsigned long keytab[16][2];

#endif	/* crypt.h */
