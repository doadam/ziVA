#include <mach/mach.h>
#import <Foundation/Foundation.h>

#ifndef __LOG_H_
#define __LOG_H_

#define LOG_LOG(tag, fmt, ...) NSLog((@"[%c] %s:%s: " fmt), tag, __func__, mach_error_string(ret), ##__VA_ARGS__)

#ifdef NDEBUG
#define DEBUG_LOG(fmt, ...)
#define ERROR_LOG(fmt, ...)
#else
#define DEBUG_LOG(fmt, ...) LOG_LOG('+', fmt, ##__VA_ARGS__)
#define ERROR_LOG(fmt, ...) LOG_LOG('-', fmt, ##__VA_ARGS__)
#endif /* NDEBUG */

#endif /* __LOG_H_ */
