#ifndef KERNEL_FILTER_LISTENER_H__
#define KERNEL_FILTER_LISTENER_H__

#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <atomic>
#include <sys/socket.h>
#include <sys/uio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <cstring>
#include <stdexcept>
#include <errno.h>
#include <iostream>
#include <linux/rtnetlink.h>

#define NETLINK_USER 31

class KernelModuleClient
{

public:
	void Run(std::atomic_bool& stopFlag);
};

#endif

