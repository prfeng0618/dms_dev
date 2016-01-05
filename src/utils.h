#ifndef _ZIGBEE_SDK_UTILS_H_
#define _ZIGBEE_SDK_UTILS_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>

enum LOG_LEVEL {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_VERBOSE,
    LOG_LEVEL_RESERVE,
    LOG_LEVEL_MAX = 0x7FFFFFFF
};

static const char* level_string[] = {
    "E",
    "W",
    "I",
    "D",
    "V",
    "R"
};

void UTILS_LOG(const char *tag, LOG_LEVEL level, const char *fmt, ...);

#define __PID__ getpid()

#ifdef ANDROID
#include <utils/Log.h>

#undef  LOG_TAG
#define LOG_TAG "ZigbeeSDK"

#define LOGV(fmt, ...) \
    ALOGV("%s() line %d: " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGD(fmt, ...) \
    ALOGD("%s() line %d: " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGI(fmt, ...) \
    ALOGI("%s() line %d: " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGW(fmt, ...) \
    ALOGW("%s() line %d: " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGE(fmt, ...) \
    ALOGE("%s() line %d: " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#undef  LOG_TAG
#define LOG_TAG "ZigbeeSDK"
#define LOGV(fmt...) \
    UTILS_LOG(LOG_TAG, LOG_LEVEL_VERBOSE, __FUNCTION__, __LINE__, fmt)
    //printf("V/%s[%d]: %s() line %d: " fmt, LOG_TAG, __PID__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGD(fmt...) \
    UTILS_LOG(LOG_TAG, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, fmt)
    //printf("D/%s[%d]: %s() line %d: " fmt, LOG_TAG, __PID__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGI(fmt...) \
    UTILS_LOG(LOG_TAG, LOG_LEVEL_INFO, __FUNCTION__, __LINE__, fmt)
    //printf("I/%s[%d]: %s() line %d: " fmt, LOG_TAG, __PID__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGW(fmt...) \
    UTILS_LOG(LOG_TAG, LOG_LEVEL_WARN, __FUNCTION__, __LINE__, fmt)
    //printf("W/%s[%d]: %s() line %d: " fmt, LOG_TAG, __PID__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGE(fmt...) \
    UTILS_LOG(LOG_TAG, LOG_LEVEL_ERROR, __FUNCTION__, __LINE__, fmt)
    //printf("E/%s[%d]: %s() line %d: " fmt, LOG_TAG, __PID__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

typedef int BOOL;
#define FALSE 0
#define TRUE 1

typedef int status_t;

enum {
    OK = 0,
    NO_ERROR = 0,
    UNKNOWN_ERROR = 0x80000000,
    UNINITIALIZED = 0x80000001,
    JSON_ERROR = 0x80000002,
};

// uint64_t static inline current_timestamp() {
//     struct timeval te;
//     gettimeofday(&te, NULL); // get current time
//     uint64_t milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // caculate milliseconds
//     // printf("milliseconds: %lld\n", milliseconds);
//     return milliseconds;
// }

void inline UTILS_LOG(const char *tag, LOG_LEVEL level, const char* fun, const int line, const char *fmt, ...) {
    if (level >= LOG_LEVEL_VERBOSE) {
#ifndef VERBOSE
        return;
#endif
    }

    if (level == LOG_LEVEL_DEBUG) {
#ifdef DEBUG
        ;
#elif VERBOSE
        ;
#else
        return;
#endif
    }

    char var[256];
    va_list var_args;
    va_start (var_args, fmt);
    vsprintf(var, fmt, var_args);
    printf("%s/%s[%d:%u] %s() line %d: %s\n", level_string[level], tag, __PID__, pthread_self(), fun, line, var);
    fflush(stdout);
    va_end (var_args);
}

#endif // _ZIGBEE_SDK_UTILS_H_
