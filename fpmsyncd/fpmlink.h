#ifndef __FPMLINK__
#define __FPMLINK__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <exception>

#include "fpm/fpm.h"
#include "fpminterface.h"
#include "routesync.h"
#include "zlog.h"
namespace swss
{
class FpmLink : public FpmInterface {
      public:
	const int MSG_BATCH_SIZE;
	FpmLink(RouteSync *rsync, unsigned short port = FPM_DEFAULT_PORT);
	virtual ~FpmLink();

	/* Wait for connection (blocking) */
	void accept();

	int getFd() override;
	uint64_t readData() override;
	/* readMe throws FpmConnectionClosedException when connection is lost */
	class FpmConnectionClosedException : public std::exception {
	};

	/* Check if the netlink message needs to be processed as raw format */
	bool isRawProcessing(struct nlmsghdr *h);

	void processRawMsg(struct nlmsghdr *h)
	{
		m_routesync->onMsgRaw(h);
	};

	void processFpmMessage(fpm_msg_hdr_t *hdr);


      private:
	RouteSync *m_routesync;
	unsigned int m_bufSize; /* Size of m_messageBuffer */
	char *m_messageBuffer;	/* Buffer for incoming messages */
	unsigned int m_pos;	/* Current position in m_messageBuffer */

	bool m_connected;	 /* Connection established status */
	bool m_server_up;	 /* Server socket created */
	int m_server_socket;	 /* Fpmlink server listen socket */
	int m_connection_socket; /* Fpmlink connection socket */
};

}

#endif
