#pragma once

#include "swss/selectable.h"
#include <libnl3/netlink/netlink.h>

#include "fpm/fpm.h"

namespace swss
{
/**
 * @brief FPM zebra communication interface
 */
class FpmInterface : public Selectable {
      public:
	virtual ~FpmInterface() = default;
};

}
