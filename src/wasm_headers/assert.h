#ifndef ASSERT_H
#define ASSERT_H

#ifdef NDEBUG
#define assert(expr) ((void)0)
#else
// In debug mode, abort on assertion failure
void abort(void);
#define assert(expr) ((expr) ? (void)0 : abort())
#endif

#endif // ASSERT_H