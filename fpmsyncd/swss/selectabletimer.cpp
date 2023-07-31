#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <system_error>


#include "selectabletimer.h"
#include "zlog.h"
namespace swss
{
#define ABORT_IF_NOT(x, fmt, args...)                                          \
	if (!(x)) {                                                            \
		int e = errno;                                                 \
		err_exit(__FUNCTION__, __LINE__, e, (fmt), ##args);            \
	}
void err_exit(const char *fn, int ln, int e, const char *fmt, ...)
{
	va_list ap;
	char buff[1024];
	size_t len;

	va_start(ap, fmt);
	snprintf(buff, sizeof(buff), "%s::%d err(%d/%s): ", fn, ln, e,
		 strerror(e));
	len = strlen(buff);
	vsnprintf(buff + len, sizeof(buff) - len, fmt, ap);
	va_end(ap);
	zlog_err("Aborting: %s", buff);
	abort();
}
SelectableTimer::SelectableTimer(const timespec &interval, int pri)
	: Selectable(pri)
	, m_zero({ { 0, 0 }, { 0, 0 } })
{
	// Create the timer
	m_tfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (m_tfd == -1) {
		throw std::system_error(make_error_code(std::errc::bad_message),
					"failed to create timerfd");
	}
	setInterval(interval);
	m_running = false;
}

SelectableTimer::~SelectableTimer()
{
	int err;

	do {
		err = close(m_tfd);
	} while (err == -1 && errno == EINTR);
}

void SelectableTimer::start()
{
	m_mutex.lock();
	if (!m_running) {
		// Set the timer interval and the timer is automatically started
		int rc = timerfd_settime(m_tfd, 0, &m_interval, NULL);
		if (rc == -1) {
			throw std::system_error(make_error_code(
							std::errc::bad_message),
						"failed to set timerfd");
		} else {
			m_running = true;
		}
	}
	m_mutex.unlock();
}

void SelectableTimer::stop()
{
	m_mutex.lock();
	if (m_running) {
		// Set the timer interval and the timer is automatically started
		int rc = timerfd_settime(m_tfd, 0, &m_zero, NULL);
		if (rc == -1) {
			// SWSS_LOG_THROW("failed to set timerfd to zero, errno: %s", strerror(errno));
			throw std::system_error(make_error_code(
							std::errc::bad_message),
						"failed to set timerfd to zero");

		} else {
			m_running = false;
		}
	}
	m_mutex.unlock();
}

void SelectableTimer::reset()
{
	stop();
	start();
}

void SelectableTimer::setInterval(const timespec &interval)
{
	// The initial expiration and intervals to caller specified
	m_interval.it_value = interval;
	m_interval.it_interval = interval;
}

int SelectableTimer::getFd()
{
	return m_tfd;
}

uint64_t SelectableTimer::readData()
{
	uint64_t cnt = 0;

	ssize_t ret;
	errno = 0;
	do {
		ret = read(m_tfd, &cnt, sizeof(uint64_t));
	} while (ret == -1 && errno == EINTR);

	ABORT_IF_NOT((ret == 0) || (ret == sizeof(uint64_t)),
		     "Failed to read timerfd. ret=%zd", ret);

	// cnt = count of timer events happened since last read.
	return cnt;
}

}
