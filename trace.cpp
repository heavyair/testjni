#include "trace.h"
#include <iostream>
#include <stdarg.h>
#include <stdio.h>

#ifdef _DEBUG
bool _trace(char *format, ...)
{
   char buffer[1000];

     va_list args;
     va_start (args, format);
     vsnprintf (buffer,256,format, args);
//     perror (buffer);

   std::clog << buffer << std::flush;
   va_end (args);

   return true;
}
#endif
