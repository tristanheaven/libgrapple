#include "grapple_certificate.h"

#include <stdlib.h>

int grapple_certificate_dispose(grapple_certificate *target)
{
  if (target->serial)
    free(target->serial);
  if (target->issuer)
    free(target->issuer);
  if (target->subject)
    free(target->subject);

  free(target);

  return 1;
}
