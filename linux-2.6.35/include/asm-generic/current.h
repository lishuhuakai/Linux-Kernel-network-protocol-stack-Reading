#ifndef __ASM_GENERIC_CURRENT_H
#define __ASM_GENERIC_CURRENT_H

#include <linux/thread_info.h>

#define get_current() (current_thread_info()->task) /* 当前进程的task_struct结构 */
#define current get_current()

#endif /* __ASM_GENERIC_CURRENT_H */
