#include <alloca.h>

#include <sys/mman.h>

#define __OR_RSHIFT__(n, x) ((x) | (x) >> n)
#define FIRST_UNUSED_BIT(x)                                                    \
  (1 +                                                                         \
   __OR_RSHIFT__(                                                              \
       16, __OR_RSHIFT__(                                                      \
               8, __OR_RSHIFT__(4, __OR_RSHIFT__(2, __OR_RSHIFT__(1, x))))))

void show_mappings(void);

enum {
  MPROT_0 = 0,                                             // not found at all
  MPROT_R = PROT_READ,                                     // readable
  MPROT_W = PROT_WRITE,                                    // writable
  MPROT_X = PROT_EXEC,                                     // executable
  MPROT_S = FIRST_UNUSED_BIT(MPROT_R | MPROT_W | MPROT_X), // shared
  MPROT_P = MPROT_S << 1,                                  // private
};

// returns a non-zero value if the address is mapped (because either MPROT_P or
// MPROT_S will be set for valid addresses)
unsigned int read_mprotection(const void *addr);

// check memory protection against the mask
// returns true if all bits corresponding to non-zero bits in the mask
// are the same in prot and read_mprotection(addr)
int has_mprotection(const void *addr, unsigned int prot,
                    unsigned int prot_mask);

// convert the protection mask into a string. Uses alloca(), no need to free()
// the memory!
#define mprot_tostring(x) (_mprot_tostring_((char *)alloca(8), (x)))
char *_mprot_tostring_(char *buf, unsigned int prot);