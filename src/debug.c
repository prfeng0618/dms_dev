#include "debug.h"

extern struct globals G;

void
_debug(char *filename, int line, int level, char *format, ...)
{
    char buf[28];
    va_list vlist;
    time_t ts;
	
    time(&ts);

    if (G.debuglevel >= level) {

        if (level <= LOG_WARNING) {
            fprintf(stderr, "[%d][%.24s][%u](%s:%d) ", level, ctime_r(&ts, buf), getpid(),
			    filename, line);
            va_start(vlist, format);
            vfprintf(stderr, format, vlist);
            va_end(vlist);
            fputc('\n', stderr);
        } 
		/* market_cpkgcli没有daemon方式
		else if (!G.daemon) {
            fprintf(stdout, "[%d][%.24s][%u](%s:%d) ", level, ctime_r(&ts, buf), getpid(),
			    filename, line);
            va_start(vlist, format);
            vfprintf(stdout, format, vlist);
            va_end(vlist);
            fputc('\n', stdout);
            fflush(stdout);
        }
		*/

        if (G.log_syslog) {
            openlog("market_cpkgcli", LOG_PID, G.syslog_facility);
            va_start(vlist, format);
            vsyslog(level, format, vlist);
            va_end(vlist);
            closelog();
        }
    }
}
