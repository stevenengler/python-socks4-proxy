#!/usr/bin/env python3

import argparse
import sys
import socket
import threading
import socketserver
import select
import struct

class FilledBufferException(Exception):
	pass
#

class EmptyReadException(Exception):
	pass
#

class SOCKSRequestHandler(socketserver.BaseRequestHandler):
	def debug_print(self, *args, **kwargs):
		if self.debug:
			print(*args, file=sys.stderr, **kwargs)
		#
	#
	def send_socks_reply(self, socket, reply_code):
		msg = struct.pack('!ccH4s', b'\0', reply_code, 0, b'\0\0\0\0')
		socket.sendall(msg)
	#
	def relay_data(self, client_socket, server_socket, to_client_buf, to_server_buf):
		endpoints = {}
		endpoints[client_socket] = {'read_buf':to_server_buf, 'write_buf':to_client_buf}
		endpoints[server_socket] = {'read_buf':to_client_buf, 'write_buf':to_server_buf}
		closing = False
		#
		while True:
			to_read = []
			to_write = []
			for sock in endpoints:
				if len(endpoints[sock]['read_buf']) < 100*1024:
					# buffer has space to read
					to_read.append(sock)
				#
			#
			for sock in endpoints:
				if len(endpoints[sock]['write_buf']) > 0:
					# buffer has bytes to write
					to_write.append(sock)
				#
			#
			if closing:
				# if closing, we should only write whatever data we have leftover
				to_read = []
			#
			(readable, writable, _) = select.select(to_read, to_write, [])
			#
			for sock in readable:
				data = sock.recv(10*1024)
				endpoints[sock]['read_buf'] += data
				if len(data) == 0:
					# socket closed
					del endpoints[sock]
					closing = True
				#
			#
			for sock in writable:
				write_buf = endpoints[sock]['write_buf']
				num = sock.send(write_buf)
				del write_buf[:num]
			#
			if closing:
				remaining_bytes = [len(endpoints[sock]['write_buf']) for sock in endpoints]
				if all([x == 0 for x in remaining_bytes]):
					# if there are no more bytes to write on remaining sockets
					break
				#
			#
		#
	#
	def read_bytes(self, socket, parse_fn, num_to_read_fn, buffered_bytes=b''):
		buffered_bytes = bytearray(buffered_bytes)
		# makes a copy of the data if already a bytearray
		while True:
			num_bytes = parse_fn(buffered_bytes)
			if num_bytes != None:
				result = buffered_bytes[:num_bytes]
				del buffered_bytes[:num_bytes]
				return (result, bytes(buffered_bytes))
			#
			(readable, _, _) = select.select([socket],[],[])
			assert socket in readable
			#
			to_read = num_to_read_fn(buffered_bytes)
			if to_read == 0:
				raise FilledBufferException()
			#
			data = self.request.recv(to_read)
			if len(data) == 0:
				raise EmptyReadException()
			#
			buffered_bytes += data
		#
	#
	def read_num_bytes(self, socket, num, buffered_bytes=b''):
		return self.read_bytes(self.request,
		                       lambda buf: num if len(buf)==num else None,
		                       lambda buf: num-len(buf),
		                       buffered_bytes)
	#
	def read_until_delimiter(self, socket, delim, read_max, buffered_bytes=b''):
		(result, buf) = self.read_bytes(self.request,
		                                lambda buf: buf.index(delim)+len(delim) if delim in buf else None,
		                                lambda buf: min(max(int(read_max/10), 10), max(read_max-len(buf), 0)),
		                                buffered_bytes)
		return (result[:-len(delim)], buf)
	#
	def handle(self):
		self.debug = self.server.debug
		inbuf = b''
		#
		# Get Version
		try:
			(socks_version, inbuf) = self.read_num_bytes(self.request, 1, inbuf)
		except EmptyReadException:
			self.debug_print('Empty SOCKS version, closing...')
			self.send_socks_reply(self.request, b'\x5B')
			return
		#
		if socks_version != b'\x04':
			self.debug_print('Unsupported SOCKS version ({}), closing...'.format(socks_version))
			self.send_socks_reply(self.request, b'\x5B')
			return
		#
		# Get Command
		try:
			(socks_cmd, inbuf) = self.read_num_bytes(self.request, 1, inbuf)
		except EmptyReadException:
			self.debug_print('Empty SOCKS command, closing...')
			self.send_socks_reply(self.request, b'\x5B')
			return
		#
		if socks_cmd not in (b'\x01', b'\x02'):
			self.debug_print('Incorrect SOCKS command ({}), closing...'.format(socks_cmd))
			self.send_socks_reply(self.request, b'\x5B')
			return
		#
		if socks_cmd != b'\x01':
			self.debug_print('Unsupported SOCKS command ({}), closing...'.format(socks_cmd))
			self.send_socks_reply(self.request, b'\x5B')
			return
		#
		# Get Port/IP
		try:
			(socks_port_ip, inbuf) = self.read_num_bytes(self.request, 6, inbuf)
		except EmptyReadException:
			self.debug_print('Empty SOCKS port/ip, closing...')
			self.send_socks_reply(self.request, b'\x5B')
			return
		#
		(port, ip_bytes) = struct.unpack('!H4s', socks_port_ip)
		if all([x == 0 for x in ip_bytes[:3]]) and ip_bytes[3] != 0:
			# this is a SOCKS4a request which will provide the domain later
			ip = None
		else:
			ip = socket.inet_ntoa(ip_bytes)
			assert ip != None
		#
		# Get User ID
		try:
			(socks_username, inbuf) = self.read_until_delimiter(self.request, b'\0', 100, inbuf)
		except EmptyReadException:
			self.debug_print('Empty SOCKS user id, closing...')
			self.send_socks_reply(self.request, b'\x5B')
			return
		except FilledBufferException:
			self.debug_print('SOCKS user id is too long, closing...')
			self.send_socks_reply(self.request, b'\x5B')
			return
		#
		# Get Domain
		if ip is None:
			try:
				(domain, inbuf) = self.read_until_delimiter(self.request, b'\0', 200, inbuf)
			except EmptyReadException:
				self.debug_print('Empty SOCKS domain, closing...')
				self.send_socks_reply(self.request, b'\x5B')
				return
			except FilledBufferException:
				self.debug_print('SOCKS domain is too long, closing...')
				self.send_socks_reply(self.request, b'\x5B')
				return
			#
		#
		# Make Connection
		address = (ip if ip is not None else domain.decode('utf-8'))
		remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		remote.connect((address, port))
		self.debug_print('Connected to {}:{}'.format(address, port))
		#
		# Send Reply
		self.send_socks_reply(self.request, b'\x5A')
		#
		# Proxy Data
		to_client_buf = bytearray(b'')
		to_server_buf = bytearray(inbuf)
		# assume that any extra bytes from the handshake are
		# optimistic application data
		self.relay_data(self.request, remote, to_client_buf, to_server_buf)
		#
		remote.close()
	#
#

class SOCKSServer(socketserver.ForkingMixIn, socketserver.TCPServer):
	allow_reuse_address = True
#

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Run a SOCKS4a proxy server.',
	                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('--port', type=int, default=1080, help='listen on port')
	parser.add_argument('--bind', type=str, default='127.0.0.1', help='bind to address', metavar='ADDRESS')
	parser.add_argument('--debug', action='store_true', help='log debug information')
	args = parser.parse_args()
	#
	server = SOCKSServer((args.bind, args.port), SOCKSRequestHandler)
	server.debug = args.debug
	if args.debug:
		print('SOCKS4a server listening on {}:{}'.format(*server.server_address), file=sys.stderr)
	#
	try:
		# Example: curl -x socks4a://localhost:1080 https://example.com
		server.serve_forever()
	except KeyboardInterrupt:
		print(file=sys.stderr)
	#
#
