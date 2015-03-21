#ifndef GRAPPLE_CERTIFICATE_H
#define GRAPPLE_CERTIFICATE_H

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  char *serial;
  time_t not_before;
  time_t not_after;
  char *issuer;
  char *subject;
} grapple_certificate;

#if defined(__GNUC__)
#pragma GCC visibility push(default)
#endif

extern int grapple_certificate_dispose(grapple_certificate *);

#if defined(__GNUC__)
#pragma GCC visibility pop
#endif

#ifdef __cplusplus
}
#endif

#endif
