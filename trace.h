#include <stdarg.h>
#include <cstdio>
#define _DEBUG
#ifdef _DEBUG
bool _trace(char *format, ...);
#define TRACE _trace
#else
#define TRACE false
#endif
