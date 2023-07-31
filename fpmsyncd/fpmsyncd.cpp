
/********************************************************************************
*	This code includes portions of code from the sonic-swss project, 
*	which is licensed under the Apache License, Version 2.0. 
*	The original code can be found at [https://github.com/sonic-net/sonic-swss]. 
*	The modifications to the original code are as follows: 
*	[Replace redis deliver logic to write routes to file for simulating fpmsyncd].
********************************************************************************/

#include <cstring>
#include <iostream>
#include <inttypes.h>
#include "swss/select.h"
#include "swss/selectabletimer.h"
#include "swss/netdispatcher.h"
#include "swss/netlink.h"
#include "fpmlink.h"
#include "routesync.h"
#include "zlog.h"
#include <getopt.h>
#include <netlink/route/route.h>
#include <string>

using namespace std;
using namespace swss;


struct option longopts[] = { { "help", no_argument, NULL, 'h' },
			     { "debug", no_argument, NULL, 'd' },
			     { "file", required_argument, NULL, 'f' },
			     { 0 } };

void usage(const char *progname, int exit_code)
{
	printf("Usage : %s [OPTION...]\n\
	-f --file <output file path>\n\
	-d --debug\n\
	-h --help\n",
	       progname);
	exit(exit_code);
}

int main(int argc, char **argv)
{
	bool debug_mode = false;
	char *output_file_path = NULL;
	while (1) {
		int opt;
		opt = getopt_long(argc, argv, "f:dh", longopts, 0);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 'f':
			output_file_path = optarg;
			break;
		case 'd':
			debug_mode = true;
			break;
		case 'h':
			usage("fpmsyncd", 1);
			break;
		default:
			usage("fpmsyncd", 1);
			break;
		}
	}


	if (debug_mode) {
		zlog_aux_init("FPMSYNCD", LOG_DEBUG);
		zlog_info("Log level set to debug");
	} else {
		zlog_aux_init("FPMSYNCD", LOG_INFO);
		zlog_info("Log level set to info");
	}


	zlog_info("FPMSYNCD starting");
	if (output_file_path == NULL) {
		zlog_err("Output file path not specified");
		usage("fpmsyncd", 1);
	} else if (access(output_file_path, F_OK) == -1) {
		zlog_err("Output file path:%s does not exist", output_file_path);
		usage("fpmsyncd", 1);
	} else {
		if (output_file_path[strlen(output_file_path) - 1] == '/')
			strcat(output_file_path, "routes.json");
		else
			strcat(output_file_path, "/routes.json");
		// clear file
		zlog_info("Clearing file %s", output_file_path);
		std::ofstream(output_file_path,
			      std::ofstream::out | std::ofstream::trunc);
		zlog_info("Output file path: %s", output_file_path);
	}

	/* Init routesync */
	RouteSync sync(output_file_path);
	/* Init netlink */
	NetLink netlink;

	netlink.registerGroup(RTNLGRP_LINK);

	/* Register netlink message handlers base on netlink msg type*/
	NetDispatcher::getInstance().registerMessageHandler(RTM_NEWROUTE, &sync);
	NetDispatcher::getInstance().registerMessageHandler(RTM_DELROUTE, &sync);
	NetDispatcher::getInstance().registerMessageHandler(RTM_NEWLINK, &sync);
	NetDispatcher::getInstance().registerMessageHandler(RTM_DELLINK, &sync);

	rtnl_route_read_protocol_names(DefaultRtProtoPath);


	while (true) {
		try {
			/* Init Fpmlink */
			FpmLink fpm(&sync);
			Select s;
			zlog_info("Waiting for fpm-client connection...");

			fpm.accept();

			zlog_info("Connected!");

			/* Add FPM and netlink to select */
			s.addSelectable(&fpm);
			s.addSelectable(&netlink);

			while (true) {
				Selectable *temps;
				/* Reading FPM messages forever (and calling
				 * "readMe" to read them) */
				s.select(&temps);
			}
		} catch (FpmLink::FpmConnectionClosedException &e) {
			zlog_err("Connection lost, reconnecting...");
		} catch (const exception &e) {
			zlog_err("Exception \"%s\" had been thrown in daemon",
				 e.what());
			return 0;
		}
	}

	return 1;
}
