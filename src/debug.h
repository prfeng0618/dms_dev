#ifndef _MARKET_DEBUG_H_
#define _MARKET_DEBUG_H_

#include <syslog.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#ifdef SYSEVENT
#include "market_sysevent_conf.h"
#endif

#ifdef CPKGCLI
#include "market_conf.h"
#endif

#include "dms_dev.h"

/** @brief Used to output messages.
 *The messages will include the finlname and line number, and will be sent to syslog if so configured in the config file 
 */
#define debug(level, format...) _debug(__FILE__, __LINE__, level, format)

/** @internal */
void _debug(char *filename, int line, int level, char *format, ...);

#endif /* _MARKET_DEBUG_H_ */