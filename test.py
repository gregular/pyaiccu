#!/usr/bin/env python3

import tic
import logging
import sys


def main(username, password, server='tic.sixxs.net'):

	# turn logging way up so we can hear everything
	logging.basicConfig(level=logging.DEBUG)

	# create client and login
	t = tic.TICClient()
	t.login(username, password, server)

	# get and print out our tunnels
	tuns = t.tunnels
	print(tuns)
	for tun in tuns:
		print(t.tunnel(tun['tunnel_id']))

	# get and print out our routes
	routes = t.routes
	print(routes)
	for route in routes:
		print(t.route(route['route_id']))

	# get all pops, only get details on one pop
	pops = t.pops
	print(pops)
	print(t.pop(pops[0]))

	# bail
	t.logout()

if __name__ == '__main__':
	main(sys.argv[1:0])
