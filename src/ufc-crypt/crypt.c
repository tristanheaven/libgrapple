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

#include "crypt.h"
#include "crypt_util.h"

#define SBA(sb, v) (*(unsigned long*)((char*)(sb)+(v)))

#define F(I, O1, O2, SBX, SBY)                                        \
    s = *k++ ^ I;                                                     \
    O1 ^= SBA(SBX, (s & 0xffff)); O2 ^= SBA(SBX, ((s & 0xffff) + 4)); \
    O1 ^= SBA(SBY, (s >>= 16));   O2 ^= SBA(SBY, ((s)          + 4));

#define G(I1, I2, O1, O2)                                             \
        F(I1, O1, O2, sb1, sb0) F(I2, O1, O2, sb3, sb2)

#define H G(r1, r2, l1, l2) ; G(l1, l2, r1, r2)

char *ufc_crypt(const char *key, const char *salt)
  { unsigned long l1, l2, r1, r2, i, j, s, *k;

    setup_salt(salt);
    mk_keytab(key);

    l1=l2=r1=r2=0;

    for(j=0; j<25; j++) {
      k = &keytab[0][0];
      for(i=8; i--; ) {
	H;
      }
      s=l1; l1=r1; r1=s; s=l2; l2=r2; r2=s;
    }

    return output_conversion(l1, l2, r1, r2, salt);
  }
