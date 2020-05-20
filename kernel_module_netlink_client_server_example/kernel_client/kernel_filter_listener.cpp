#include <atomic>
#include <iostream>
#include <signal.h>

#include "kernel_filter_listener.h"

std::atomic_bool stopFlag(false);

void SignalHandler(int signo)
{
	if (signo == SIGINT || signo == SIGTERM)
	{
		stopFlag = true;
	}
}

int main(int argc, char* argv[])
{
	if (signal(SIGINT, SignalHandler) == SIG_ERR)
		return -1;

	if (signal(SIGTERM, SignalHandler) == SIG_ERR)
		return -1;

	try
	{
		KernelModuleClient kernelModuleClient;
		kernelModuleClient.Run(stopFlag);	
	}
	catch(std::exception& ex)
	{
		std::cout << "exception " << ex.what() << std::endl;
	}

	return 0;
}

	void KernelModuleClient::KernelModuleClient(std::atomic_bool& stopFlag)
	{		
		struct sockaddr_nl src_addr, dest_addr;
		struct nlmsghdr *nlh = NULL;
		struct iovec iov;
		struct msghdr msg;

		int sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
		if(sock_fd < 0)
		{
			std::cout << "can't create socket\n";
			return;
		}

		memset(&src_addr, 0, sizeof(src_addr));
		src_addr.nl_family = AF_NETLINK;
		src_addr.nl_pid = getpid(); /* self pid */

		bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
		memset(&dest_addr, 0, sizeof(dest_addr));
		memset(&dest_addr, 0, sizeof(dest_addr));
		dest_addr.nl_family = AF_NETLINK;
		dest_addr.nl_pid = 0; /* For Linux Kernel */
		dest_addr.nl_groups = 0; /* unicast */

		nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(1024));
		memset(nlh, 0, NLMSG_SPACE(1024));
		nlh->nlmsg_len = NLMSG_SPACE(1024);
		nlh->nlmsg_pid = getpid();
		nlh->nlmsg_flags = 0;

		iov.iov_base = (void *)nlh;
		iov.iov_len = nlh->nlmsg_len;

                memset(&msg, 0, sizeof(msg));
		msg.msg_name = (void *)&dest_addr;
		msg.msg_namelen = sizeof(dest_addr);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		ssize_t result = sendmsg(sock_fd,&msg,0);
		if (result < 0)
		{
			std::cout << "send pid to kernel failed " << strerror(errno) << std::endl;
                        close(sock_fd);
		        free(nlh);

			return;
		}

		while(!stopFlag)
		{
			ssize_t recvResult = recvmsg(sock_fd, &msg, 0);
			if (recvResult < 0)
			{
				std::cout << "error recv msg from kernel " << strerror(errno) << std::endl;
				break;
			} 

			const char* data = (const char *)NLMSG_DATA(nlh);
                        std::cout << "packet payload " << data;
		}

		close(sock_fd);
		free(nlh);
	}

