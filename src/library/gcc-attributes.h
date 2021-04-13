#ifndef GCC_ATTRIBUTES_H
#define GCC_ATTRIBUTES_H

#define NEVERNULL __attribute__ ((returns_nonnull))
#define WARNUNUSED __attribute__ ((warn_unused_result))

// MALLOCLIKE has some constraints on it's use. It must be returning memory
// that is freshly allocated and it must not contain valid pointers of any
// kind at the time of return. It's OK for them to be set to NULL, though.
// Also, pointers can be added to the buffer by other functions after the
// data is returned. For example, if you malloc a structure and strdup
// something to a member of that structure, you cannot use MALLOCLIKE. Doing
// so will cause a hard to find heisenbug. An example of good use is allocating
// memory and copying non-pointer data values into it and then returning the
// memory. This use is fine.
#define MALLOCLIKE __attribute__ ((malloc))
#define NORETURN __attribute__ ((noreturn))

#endif
