#ifndef __ROUTESYNC__
#define __ROUTESYNC__


#include "swss/netmsg.h"
#include "fpminterface.h"
#include <string.h>
#include <bits/stdc++.h>
#include <netlink/route/route.h>
#include "json.hpp"
#include "zlog.h"
// Add RTM_F_OFFLOAD define if it is not there.
// Debian buster does not provide one but it is neccessary for compilation.
#ifndef RTM_F_OFFLOAD
#define RTM_F_OFFLOAD 0x4000 /* route is offloaded */
#endif

using namespace std;

/* Parse the Raw netlink msg */
extern void netlink_parse_rtattr(struct rtattr **tb, int max,
				 struct rtattr *rta, int len);


namespace swss
{
/* Path to protocol name database provided by iproute2 */
constexpr auto DefaultRtProtoPath = "/etc/iproute2/rt_protos";

/* Ring buffer is used to buffer route */
template <typename DataType, int Length = 100000> class RingBuffer {
      private:
	DataType datas[Length];
	int head = 0;
	int tail = 0;
	int count = 0;

      public:
	bool is_full()
	{
		return (tail + 1) % Length == head;
	}
	bool is_empty()
	{
		return tail == head;
	}
	bool push(DataType data)
	{
		if (is_full())
			return false;
		datas[tail] = data;
		tail = (tail + 1) % Length;

		return true;
	}
	bool pop(DataType &data)
	{
		if (is_empty())
			return false;
		data = datas[head];
		head = (head + 1) % Length;
		return true;
	}
	int size()
	{
		if (tail >= head)
			return tail - head;
		else
			return tail + Length - head;
	}
};


//ATTENTION: Do not use zlog in thread flushtimer_t, it will cause core dump
class RouteSync : public NetMsg {
      public:
	enum { MAX_ADDR_SIZE = 64 };

	RouteSync(char *file_path = nullptr);
	~RouteSync();
	virtual void onMsg(int nlmsg_type, struct nl_object *obj,
			   struct nlmsghdr *h);
	virtual void onMsgRaw(struct nlmsghdr *obj);

	void setSuppressionEnabled(bool enabled);

	bool isSuppressionEnabled() const
	{
		return m_isSuppressionEnabled;
	}

	void onFpmConnected(FpmInterface &fpm)
	{
		m_fpmInterface = &fpm;
	}

	void onFpmDisconnected()
	{
		m_fpmInterface = nullptr;
	}

	/* Flush route msg to json file */
	void fflush();
	/* Check if json file is empty */
	bool is_output_file_empty();


      private:
	struct nl_cache *m_link_cache;
	struct nl_sock *m_nl_sock;

	bool m_isSuppressionEnabled{ false };
	FpmInterface *m_fpmInterface{ nullptr };

	/* Json file path*/
	char *m_output_file_path;
	/* Json file stream*/
	std::ofstream m_output_file;
	/* Buffer to store route msg */
	RingBuffer<nlohmann::json> m_task_ringbuffer;
	/* Thread to flush route msg to json file */
	std::thread flushtimer_t;
	/* Thread exit flag */
	std::atomic<bool> thread_exit;

	/* Add one route json to ring buffer */
	void push_to_ringbuffer(nlohmann::json j);

	/* Handle regular route (include VRF route) */
	void onRouteMsg(int nlmsg_type, struct nl_object *obj, char *vrf,
			nlohmann::json *j);

	/* onMsgInternal will call by onMsg, when onMsgInternal return, json can write to file easily */
	void onMsgInternal(int nlmsg_type, struct nl_object *obj,
			   struct nlmsghdr *h, nlohmann::json *j);

	/* Handle label route */
	void onLabelRouteMsg(int nlmsg_type, struct nl_object *obj,
			     nlohmann::json *j);

	void parseEncap(struct rtattr *tb, uint32_t &encap_value, string &rmac);

	void parseRtAttrNested(struct rtattr **tb, int max, struct rtattr *rta);

	char *prefixMac2Str(char *mac, char *buf, int size);


	/* Handle prefix route */
	void onEvpnRouteMsg(struct nlmsghdr *h, int len, nlohmann::json *j);

	/* Handle vnet route */
	void onVnetRouteMsg(int nlmsg_type, struct nl_object *obj, string vnet,
			    nlohmann::json *j);

	/* Get interface name based on interface index */
	bool getIfName(int if_index, char *if_name, size_t name_len);

	/* Get interface if_index based on interface name */
	// rtnl_link* getLinkByName(const char *name);

	void getEvpnNextHopSep(string &nexthops, string &vni_list,
			       string &mac_list, string &intf_list);

	void getEvpnNextHopGwIf(char *gwaddr, int vni_value, string &nexthops,
				string &vni_list, string &mac_list,
				string &intf_list, string rmac, string vlan_id);

	bool getEvpnNextHop(struct nlmsghdr *h, int received_bytes,
			    struct rtattr *tb[], string &nexthops,
			    string &vni_list, string &mac_list,
			    string &intf_list);

	/* Get next hop list */
	void getNextHopList(struct rtnl_route *route_obj, string &gw_list,
			    string &mpls_list, string &intf_list);

	/* Get next hop gateway IP addresses */
	string getNextHopGw(struct rtnl_route *route_obj);

	/* Get next hop interfaces */
	string getNextHopIf(struct rtnl_route *route_obj);

	/* Get next hop weights*/
	string getNextHopWt(struct rtnl_route *route_obj);

	/* Flush thread function */
	void timer_flush_pipe();
};


}

#endif
