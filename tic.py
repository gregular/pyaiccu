#!/usr/bin/env python3 

import logging
import hashlib
import socket
import ssl
import sys
import time

class TIC(object):
	""" define some TIC constants """
	PORT = 3874
	VERSION = 'draft-00'

class TICClient(object):

	CLIENT = 'PY-AICCU'
	VERSION = '0.1'

	def __init__(self):
		self.log = logging.getLogger('TIC')
		self._state = 'disconnected'

	@property
	def state(self):
		return self._state

	def _interact(self, line, *args):
		if line:
			outline = line.format(*args)
			self.log.debug(' --> %s', outline.rstrip())
			self.sock.send(outline.encode())
		answer = self.sockfile.readline()
		self.log.debug('<--  %s', answer.rstrip())
		if answer[0] != '2':
			raise Exception('interaction failed: {}'.format(answer))
		return answer[:3],answer[4:]

	def _checktime(self, epochtime):
		CLOCK_OFF=120
		curr_time = time.time()


		# is one of the times in the loop range?
		if curr_time >= -CLOCK_OFF or epochtime >= -CLOCK_OFF:
			i = abs((curr_time + (CLOCK_OFF * 2)) - (epochtime + (CLOCK_OFF * 2)))
		else:
			i = abs(curr_time - epochtime)

		if i > CLOCK_OFF:
			self.log.warning('curr_time: {}   epochtime: {}'.format(curr_time, epochtime))
			return i
		
		# time is in the allowed range
		return 0

	def logout(self, msg=None):
		if msg == None:
			msg = 'bye'
		# server replies and immediately hangs up so we can't use _interact
		self.sock.send('QUIT {}'.format(msg).encode())
		self._state = 'disconnected'
		self.sock = None
		self.sockfile = None

	def login(self, username, password, server, **options):

		self.log.debug('Trying to connect to TIC server %s', server)

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect((server, TIC.PORT))
		self.sockfile = self.sock.makefile()

		# grab the welcome
		ret,val = self._interact(None)

		# send our client identification
		ret,val = self._interact('client TIC/{} {}/{} {}/{}\n',
				TIC.VERSION, 
				TICClient.CLIENT, TICClient.VERSION,
				sys.platform, 'Python-' + sys.version.split()[0])

		# request current time
		ret,val = self._interact('get unixtime\n')
		ret = self._checktime(int(val))
		if ret:
			msg = 'The clock is off by {} seconds, use NTP to sync it!\n'.format(ret)
			self.logout(msg)
			raise Exception(msg)

		# Upgrade to TLS if available
		#try:
		#	ret,val = self._interact('starttls\n')
		#except:
		#	# TODO: confirm if TLS was required
		#	self.log.warn('TLS unsupported')

		#if ret[0] == 2:
		#	self.sock = ssl.wrap_socket(self.sock, ssl_version=ssl.PROTOCOL_TLSv1)
		#	self.sockfile = self.sock.makefile()

		# Send our username
		ret,val = self._interact('username {}\n', username)

		# Pick a challenge
		ret,val = self._interact('challenge md5\n')
		challenge = val.rstrip() + hashlib.md5(password.encode()).hexdigest()
		signature = hashlib.md5(challenge.encode()).hexdigest()

		# Send our response
		ret,val = self._interact('authenticate md5 {}\n', signature)

		self._state = 'connected'

	@property
	def tunnels(self):
		if self._state != 'connected':
			self.log.warn('not connected')
			return []
		ret,val = self._interact('tunnel list\n')
		if ret != '201':
			self.log.warn('Could not list tunnels: %s\n', val)
			return []

		tuns = []
		for val in self.sockfile:
			self.log.debug('<-- ' + val.rstrip())
			if val[0:3] == '202': break
			fields = val.split()
			if len(fields) != 4:
				self.log.error('Wrong field format when listing tunnels\n')
				return []
			tuns.append({
				'tunnel_id': fields[0],
				'ipv6_endpoint': fields[1],
				'ipv4_endpoint': fields[2],
				'pop_name': fields[3]
			})
		return tuns

	def tunnel(self, id):
		if self._state != 'connected':
			self.log.warn('not connected')
			return []
		ret,val = self._interact('tunnel show {}\n', id)
		tun = {}
		for val in self.sockfile:
			self.log.debug('<-- ' + val.rstrip())
			if val[0:3] == '202': break
			key,data = val.rstrip().split(':', 1)
			tun[key] = data.lstrip()
		return tun

	@property
	def routes(self):
		if self._state != 'connected':
			self.log.warn('not connected')
			return []
		ret,val = self._interact('route list\n')
		if ret != '201':
			self.log.warn('Could not list routes: %s\n', val)
			return []

		rts = []
		for val in self.sockfile:
			self.log.debug('<-- ' + val.rstrip())
			if val[0:3] == '202': break
			fields = val.split()
			if len(fields) != 3:
				self.log.error('Wrong field format when listing routes\n')
				return []
			rts.append({
				'route_id': fields[0],
				'tunnel_id': fields[1],
				'route_prefix': fields[2]
			})
		return rts

	def route(self, id):
		if self._state != 'connected':
			self.log.warn('not connected')
			return []
		ret,val = self._interact('route show {}\n', id)
		rt = {}
		for val in self.sockfile:
			self.log.debug('<-- ' + val.rstrip())
			if val[0:3] == '202': break
			key,data = val.rstrip().split(':', 1)
			rt[key] = data.lstrip()
		return rt
