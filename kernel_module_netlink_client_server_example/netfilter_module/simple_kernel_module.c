#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/byteorder/generic.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/netlink.h>
#include <linux/netlink.h>

#define NETLINK_USER 31
#define CUSTOM_GROUP 4444

struct sock *nl_sk = NULL;
static loff_t pos=0;
static int clientPid = -1;

static void print_ip(int ip, char* out, size_t len)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    snprintf(out, len, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);        
}

static const unsigned int TcpProto = 6;

static unsigned int HookFunc(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn) (struct sk_buff *))
{
	char srcIp[16];
	char dstIp[16];

	struct iphdr* ipHeader = (struct iphdr*)skb_network_header(skb);
	print_ip(ipHeader->saddr, srcIp, sizeof(srcIp));
	print_ip(ipHeader->daddr, dstIp, sizeof(dstIp));

	if (ipHeader->protocol == TcpProto)
	{
		skb_set_transport_header(skb, ipHeader->ihl * 4);
		struct tcphdr* tcpHeader = (struct tcphdr *)skb_transport_header(skb);
		if (htons(tcpHeader->source) == 4444)
		{
			char msg[1024];
			int msgWritten = snprintf(msg, sizeof(msg), "event_type=network network_subtype=flow network_protocol=%d network_source_address=%s network_source_port=%d network_destination_address=%s network_destination_port=%d", ipHeader->protocol, srcIp, htons(tcpHeader->source), dstIp, htons(tcpHeader->dest));
			const int tcpDataLen = ntohs(ipHeader->tot_len) - (tcpHeader->doff * 4) - (ipHeader->ihl * 4);
			if (tcpDataLen > 0)
			{
				const char* data = (char *)((unsigned char *)tcpHeader + (tcpHeader->doff * 4));	
				const char* PayloadHeader = " network_payload=";
				snprintf(msg + msgWritten, strlen(PayloadHeader) + tcpDataLen, "%s%s", PayloadHeader, data);
			}

			if (clientPid > 0)
			{
				size_t msg_size = strlen(msg);
				struct sk_buff* skb_out = nlmsg_new(msg_size,0);

				if(!skb_out)
				{

				    printk(KERN_ERR "Failed to allocate new skb\n");
				    return NF_ACCEPT;

				} 
				struct nlmsghdr *nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0);  
				NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
				strncpy(nlmsg_data(nlh),msg,msg_size);

				int res=nlmsg_unicast(nl_sk,skb_out,clientPid);

				if(res < 0)
				    printk(KERN_INFO "Error while sending bak to user\n");
			}
			else
			{
				printk(KERN_EMERG , msg);
			}

			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook       = HookFunc,
    .hooknum    = 1, /* NF_IP_LOCAL_IN */
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,
};

static void GetClientPid(struct sk_buff *skb) 
{
	struct nlmsghdr *nlh = (struct nlmsghdr*)skb->data;
	clientPid = nlh->nlmsg_pid;

	printk(KERN_EMERG "client connected with pid %d\n", clientPid);
}

static int __init MyInit(void)
{

	nf_register_hook(&nfho);
	
	struct netlink_kernel_cfg cfg = {
		.groups = 0,
    		.input = GetClientPid,
	};

	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	if (!nl_sk)
	{
		printk(KERN_EMERG "kernel socket failed\n");
		return -10;
	}

	printk(KERN_EMERG "netfilter module registered\n");
	return 0;
}

static void __exit MyExit(void)
{
	nf_unregister_hook(&nfho);
	netlink_kernel_release(nl_sk); 
}

module_init(MyInit);
module_exit(MyExit);
