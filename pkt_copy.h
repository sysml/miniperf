#ifndef _PKT_COPY_H_
#define _PKT_COPY_H_

#ifdef __cplusplus
extern "C" {
#endif

static inline void
pkt_copy16(const void *_src, void *_dst, int l)
{
	const uint64_t *src = (uint64_t *) _src;
	uint64_t *dst = (uint64_t *) _dst;
#ifndef likely    
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)       __builtin_expect(!!(x), 0)
#endif
	for (; l > 0; l-=16) {
		*dst++ = *src++;
		*dst++ = *src++;
	}

}

static inline void
pkt_copy32(const void *_src, void *_dst, int l)
{
	const uint64_t *src = (uint64_t *) _src;
	uint64_t *dst = (uint64_t *) _dst;
#ifndef likely    
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)       __builtin_expect(!!(x), 0)
#endif
	for (; l > 0; l-=32) {
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
	}

}

static inline void
pkt_copy64(const void *_src, void *_dst, int l)
{
	const uint64_t *src = (uint64_t *) _src;
	uint64_t *dst = (uint64_t *) _dst;
#ifndef likely    
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)       __builtin_expect(!!(x), 0)
#endif
	for (; l > 0; l-=64) {
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
	}
}

#include <xmmintrin.h>

// Not working XXX
static inline void
sse2_pkt_copy(const void *_src, void* _dst)
{
    __m128 *dst = (__m128*) _dst;
    const __m128 *src = (__m128*) _src;
    
    *dst++ = *src++; 
    *dst++ = *src++; 
    *dst++ = *src++; 
    *dst++ = *src++; 
}

#define pkt_copy(src, dst, l) pkt_copy64(src, dst, l)

#ifdef __cplusplus
}
#endif

#endif
