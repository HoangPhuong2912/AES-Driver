#include <linux/module.h>
#include <linux/kernel.h>

static int myinit(void)
{
	pr_info("panic init\n");
	panic("hello panic");
	return 0;
}

static void myexit(void)
{
	pr_info("panic cleanup\n");
}

module_init(myinit);
module_exit(myexit);
MODULE_LICENSE("GPL");
