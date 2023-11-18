/** Base64 converter */

#include <stdlib.h>

extern size_t base64_encode(char *dst, size_t cap, const void *src, size_t len);
extern size_t base64url_encode(char *dst, size_t cap, const void *src, size_t len);
