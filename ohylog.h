#ifndef _OHY_LOG_H
#define _OHY_LOG_H

#include "linux/kernel.h"

#define OHY_LOG_TAG_INTERCEPTOR_LAYER "ohayas_interceptor:"
#define OHY_LOG_TAG_SYS_ERROR "ohayas_error:"
#define OHY_LOG_TAG_MAIN "ohayas_main:"

#define OHY_LOG_KERN_INFO(__VA_ARGS__) printk(KERN_INFO __VA_ARGS__);
#define OHY_LOG_KERN_ALRT(__VA_ARGS__) printk(KERN_ALERT __VA_ARGS__);

#endif