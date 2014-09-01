#!/usr/bin/env python
# -*- coding: utf-8 -*-
#~ from twisted.internet import iocpreactor
#~ iocpreactor.install()
from twisted.internet import reactor, protocol, defer
from twisted.web.proxy import Proxy, ProxyClient, ProxyClientFactory
from twisted.web.http import HTTPFactory, HTTPChannel, Request, HTTPClient
from twisted.python import log
import urlparse
import sys
import json
import struct
import warnings
from cryptography.fernet import Fernet
#ClientFactory is complex, has many init variable
#Client in pool should talk to Transport in pool
# cloud recv a minus : New Stream, local recv a minus : Old Stream End
# cryptography GCB tag, iv, key, authtext, 16,4, 

#send wrong, using dict
#send back is wrong in that the callback cum is wrong
#bug comes from state code part and deal with minus number
#http's transferqueue = > finish()
#http local close remote still open for the stream
#http t.co can't redirect
#both close and connection Lost wrong

CLOUD_HOST = '127.0.0.1'
CLOUD_PORT = 8083
DKEY = Fernet.generate_key()
VERIFY_SIZE = 0

class ProxyClient2(ProxyClient):
    def __init__(self, *args):
	ProxyClient.__init__(self, *args)
	if not self.father.channel:
	    self.father.finish = self.connectionMade = lambda *args: None
	d = self.father.notifyFinish()
	def on_err(ignore):
	    log.msg('called++++++++')
	    log.msg(self.father.getRequestHostname())
	    self._finished = True
	    self.transport.loseConnection()
	d.addErrback(on_err)
	#~ print 'inited a ProxyClient2:', self.father.getRequestHostname(), self.father.channel
	
ProxyClientFactory.protocol = ProxyClient2
    
class Proxy2(Proxy):
    is_ssl = False
    
    def connectionMade(self):
	Proxy.connectionMade(self)
	self.client_factories = []
    
    def dataReceived(self, data):
	if self.client_factories and self.is_ssl:
	    #~ print 'ssl data'
	    self.client_factories[-1].after_conn.addCallback(lambda ignore:self.client_factories[-1].transfer(data))
	    return
	else:
	    Proxy.dataReceived(self, data)
	    
    def allContentReceived(self):
	#~ if 'player' in self._path:
	    #~ print ''.join(self.contents)
	if self._command == 'CONNECT':
	    log.msg('https:', self._path)
	    host, port = split_path(self._path)
	    #~ print host, port
	    self.is_ssl = True
	    self.client_factories.append(SslFetcherFactory(self))
	    reactor.connectTCP(host, port, self.client_factories[-1])
	    self.transport.write("HTTP/1.1 200 OK\r\n\r\n")
	else:
	    Proxy.allContentReceived(self)
	    
    def connectionLost(self, reason):
	if self.is_ssl:
	    self.client_factories[-1].after_conn.addCallback(lambda ignore:self.client_factories[-1].child.loseConnection())
	else:
	    Proxy.connectionLost(self, reason)
	    self.dataReceived = lambda *args: None
	
class Fetcher(protocol.Protocol):
    
    def __init__(self, father, factory):
	self.father = father
	self.factory = factory
	
    def send_data(self, value):
	#~ log.msg('Fetcher sent data')
	self.transport.write(value)
	#~ print 'value sent'
	
    def connectionMade(self):
	#~ print 'client connected'
	#~ print 'open:', self.transport.getPeer()
	self.factory.after_conn.callback(self)
	#~ print 'ssl connected'
	
    def connectionLost(self, reason):
	if self.father.is_ssl:
	    self.father.transport.loseConnection()
	
    
    def dataReceived(self, value):
	#~ log.msg('<-Outest', len(value))
	self.father.write(value)
	#~ print 'send back'
	
class FetcherFactory(protocol.ClientFactory):
    protocol = Fetcher
    
    def __init__(self, server):
	self.server = server
	self.after_conn = defer.Deferred()
	self.after_lost = defer.Deferred()
	
    def buildProtocol(self, addr):
	self.child = self.protocol(self.server, self)
	return self.child
	
    def transfer(self, data):
	self.child.transport.write(data)
	#~ log.msg('++Data:', len(data))
	
    def clientConnectionFailed(self, connector, reason):
	#~ self.server.transport.loseConnection()
	self.server.handle_close(source='here')
	
	
def split_path(hostport):
    host, port = hostport.split(':')
    return host, int(port)
	
class TransferContract(protocol.Protocol):
    SIZE_STATE = 0
    BODY_STATE = 1
    DISCARD_STATE = 2
    #~ MAIN_STATE = 3
    #~ DECRYPT_STATE = 4
    
    def connectionMade(self):
	self.body_size = 0
	self.verify_tag = ''
	self.here_closed = False
	self.remote_closed = False
	self.has_header = False
	self._trans_buff = ''
	self._trans_state = self.SIZE_STATE
	self.crypt_tool = Fernet(DKEY)
	
    def dataReceived(self, data):
	self._trans_buff += data
	
	if self._trans_state == self.SIZE_STATE:
	    d = self.read_bytes(VERIFY_SIZE + 4)
	    d.addErrback(self.after_error)
	    d.addCallback(self.got_size_data)
	elif self._trans_state == self.BODY_STATE:
	    d = self.read_bytes(self.body_size)
	    d.addCallback(self.got_unchecked_body_data)
	    d.addErrback(self.after_error)
	elif self._trans_state == self.DISCARD_STATE:
	    d = self.read_bytes(self.body_size)
	    d.addCallback(lambda ignore: self.set_status(self.SIZE_STATE))
	    d.addErrback(self.after_error)
	    
    
    def after_error(self, reason):
	log.msg('>>>>>>>>>>>>>>>>>>>>>>>>>Current State:' + str(self._trans_state))
	log.msg(reason)
	
    def got_size_data(self, data):
	self.verify_tag, encrypted_bytes = data[:VERIFY_SIZE], data[VERIFY_SIZE:]
	size_bytes = self.decrypt(encrypted_bytes)
	self.body_size = struct.unpack('i', size_bytes)[0]
	#~ log.msg('<->body', self.body_size)
	#~ log.msg('here closed', self.here_closed)
	
	#bug below, after reboot, cloud get header ,get body and no action continue
	if self.body_size > 0 and not self.here_closed:
	    self.set_status(self.BODY_STATE)
	elif self.body_size < 0:
	    self.body_size = 0 - self.body_size
	    self.handle_close(source='remote')
	    self.set_status(self.DISCARD_STATE)
	else:
	    self.set_status(self.DISCARD_STATE)

	
    def got_unchecked_body_data(self, data):
	comfortable_data = self.decrypt(data)
	if self.verify_body_data(comfortable_data):
	    self.parse_data(comfortable_data)
	    self.set_status(self.SIZE_STATE)
	else:
	    self.verify_failed(comfortable_data)
    
    def parse_data(self, data):
	#to change has_header
	raise NotImplementedError()
	
    def verify_body_data(self, data):
	return True
	
    def verify_failed(self, data):
	pass

	
    def after_header_data_old(self, result):
	self.header = json.loads(result)
	if self.header_size > 100:
	    log.msg('just after size', self.header)
	log.msg('just after header', self.header)
	self.parse_header()
	if self.header['encrypted_size'] == 0:
	    self.set_status(self.MAIN_STATE)
	else:
	    self.decrypted_size = self.header['encrypted_size']
	    self.set_status(self.DECRYPT_STATE)
	
    def read_bytes(self, length):
	assert length > 0
	d = defer.Deferred()
	if len(self._trans_buff) >= length:
	    result_data, self._trans_buff = self._trans_buff[:length], self._trans_buff[length:]
	    d.callback(result_data)
	return d
	
    def set_status(self, next_state):
	self._trans_state = next_state
	if len(self._trans_buff) > 0:
	    self.dataReceived('')
	    
    def send_encrypted_old(self, header, need_encrypted_data, contents):
	encrypted_data = self.encrypt(need_encrypted_data)
	header['encrypted_size'] = len(encrypted_data)
	#~ log.msg('sent header size:', len(encrypted_data))
	trans_header = json.dumps(header)
	self.transport.write(struct.pack('I', len(trans_header)))
	self.transport.write(trans_header)
	self.transport.write(encrypted_data)
	self.transport.write(contents)
	
    #~ def send(self, data):
	#~ self.send_encrypted(data)
	#~ log.msg('cloud send back data')
	
    def decrypt(self, data):
	#~ return self.crypt_tool.decrypt(data)
	return data
	
    def encrypt(self, data):
	#~ return self.crypt_tool.encrypt(data)
	return data
    def transfer(self, data):
	raise NotImplementedError()
	
    def handle_close(self, source):
	if source == 'here':
	    self.here_closed = True
	elif source == 'remote':
	    self.remote_closed = True
	if self.here_closed and self.remote_closed:
	    #~ self.update()
	    #~ self.factory.pool.put(self.factory)
	    self.handle_both_close()
	elif not self.here_closed:
	    self.send_close_bytes('cancel')
	    self.handle_remote_close()
	elif not self.remote_closed:
	    self.send_close_bytes('cancel')
	
	    
	
    def send_encrypted(self, bytes_data):
	if bytes_data:
	    self.transport.write('\x00' * VERIFY_SIZE)
	    self.transport.write(struct.pack('i', len(bytes_data)))
	    self.transport.write(bytes_data)
	
    def send_close_bytes(self, bytes_data):
	self.transport.write(struct.pack('i', len(bytes_data) * -1))
	self.transport.write(bytes_data)
	    
    def handle_remote_close(self):
	raise NotImplementedError()
	
    def handle_both_close(self):
	raise NotImplementedError()


class TransferPool(object):
    def __init__(self, factory_class):
	self.factory_class = factory_class
	self._pool = []
	
    def get(self, *args, **kargs):
	if self._pool:
	    old_one = self._pool.pop(0)
	    #~ log.msg('old_one_disconnected:' , old_one.father._disconnected)
	    log.msg('Pool Wins: ', len(self._pool))
	    return old_one.update(*args, **kargs)
	else:
	    new_one = self.factory_class(*args, **kargs)
	    reactor.connectTCP(CLOUD_HOST, CLOUD_PORT, new_one)
	    return new_one
	    
    def put(self, factory_obj):
	if len(self._pool) > 20:
	    factory_obj.close()
	else:
	    self._pool.append(factory_obj)
	    
class LocalTransfer(TransferContract):
    def __init__(self, factory, py_header, html_header, contents):
	self.factory = factory
	self.py_header = py_header
	self.html_header = html_header
	self.contents = contents
	
    def connectionMade(self):
	TransferContract.connectionMade(self)
	#finish modify send
	self.send_encrypted(json.dumps(self.py_header))
	self.send_encrypted(self.html_header)
	self.send_encrypted(self.contents)
	self.factory.after_conn.callback(self)
	
	
    def parse_data(self, data):
	#~ log.msg('<-loc recved clear data:', len(data))
	self.factory.father.write(data)
	
	
    def handle_remote_close(self):
	log.msg('Local: handle remote close, close local')
	self.factory.father.finish()

    def handle_both_close(self):
	log.msg('Local half rewinded:', self.py_header)
	if self.factory.father.channel2:
	    self.factory.father.channel2.factory.pool.put(self.factory)
	    #~ self.factory.father.channel2 = None
    
    def connectionLost(self, reason):
	log.msg('->Local End:', self.py_header.get('host', None))
	if self.py_header.get('host', None):
	    if self.py_header.get('host').startswith('post.'):
		log.msg(self.factory.father.channel.requests)
	self.factory.after_lost.callback(self)
	#~ self.factory.father.channel2.transport.loseConnection()
	#~ if not self.factory.father.finished:
	    #~ self.factory.father.finish()
	#~ self.factory = None
	#~ self.factory.father = None
	#~ self.factory.father.finish()
	
class LocalTransferFactory(FetcherFactory):
    
    def __init__(self, father, py_header, html_header, contents):
	self.father = father
	self.py_header = py_header
	self.html_header = html_header
	self.contents = contents
	FetcherFactory.__init__(self, father)
	
    def update(self, father, py_header, html_header, contents):
	log.msg('before sending info:', self.father, self.py_header)
	self.father = father
	self.py_header = py_header
	self.html_header = html_header
	self.contents = contents
	self.child.py_header = py_header
	self.child.html_header = html_header
	self.child.contents = contents
	self.child.set_status(self.child.SIZE_STATE)
	log.msg('value of State', self.child._trans_state)
	#~ self.child.send_encrypted(self.py_header, self.html_header, self.contents)
	log.msg('updated sending info:', self.py_header)
	self.child.body_size = 0
	self.child.verify_tag = ''
	self.child.here_closed = False
	self.child.remote_closed = False
	self.child.send_encrypted(json.dumps(self.py_header))
	self.child.send_encrypted(self.html_header)
	self.child.send_encrypted(contents)
	return self
	
    def close(self):
	self.child.transport.loseConnection()
	self.father = None
	
    def buildProtocol(self, addr):
	self.child = LocalTransfer(self, self.py_header, self.html_header, self.contents)
	return self.child
	
    def clientConnectionFailed(self, x, y):
	self.father.channel.transport.loseConnection()
	
    def startedConnecting(self, x):
	pass	    
	
	
class ProxyRequest2(Request):
    def process(self):
	is_ssl = self.method == 'CONNECT'
	parsed = urlparse.urlparse(self.uri)
	protocol = parsed[0]
	host = parsed[1]
	port = 80
	if ':' in host:
	    host, port = host.split(':')
	    port = int(port)
	rest = urlparse.urlunparse(('', '') + parsed[2:])
	if not rest:
	    rest = rest + '/'
	py_header = dict(host=host, port=int(port), is_ssl=is_ssl)	
	headers_dict = self.getAllHeaders().copy()
	headers_dict.pop('proxy-connection', None)
	headers_dict.pop('keep-alive', None)
	headers_dict["connection"] = "close"
	if 'host' not in headers_dict:
	    headers_dict['host'] = host
	headers = ["%s: %s\r\n"%(k.capitalize(), v) for k, v in headers_dict.items()]
	headers.insert(0, "%s %s %s\r\n"%(self.method, rest, self.clientproto))
	headers.append("\r\n")
	html_header = ''.join(headers)

	self.content.seek(0, 0)
	
	if is_ssl:
	    host, port = self.uri.split(':')
	    self.transport.write("HTTP/1.1 200 OK\r\n\r\n")
	    self.channel.is_ssl_mode = True
	    py_header = dict(host=host, port=int(port), is_ssl=is_ssl)
	    self.local_factory = self.channel.factory.pool.get(self, py_header, '', '')
	else:
	    self.local_factory = self.channel.factory.pool.get(self, py_header,  html_header, self.content.read())
	    #~ self.local_factory = LocalTransferFactory(self, py_header, html_header, self.content.read())
	    #~ reactor.connectTCP(CLOUD_HOST, CLOUD_PORT, self.local_factory)
	self.channel2 = self.channel
	test_d = self.notifyFinish()
	test_d.addCallback(lambda ig: self.channel2.transport.loseConnection() if len(self.channel2.requests) == 0 else None)
	test_d.addBoth(lambda ig: self.local_factory.child.handle_close(source='here'))
    
    def write(self, data):
	#~ log.msg('<-father wrote back', repr(data))
	self.transport.write(data)
	
    def finish(self):
	if self._disconnected:
	    raise RuntimeError(
		"Request.finish called on a request after its connection was lost; "
		"use Request.notifyFinish to keep track of this.")
	if self.finished:
	    warnings.warn("Warning! request.finish called twice.", stacklevel=2)
	    return

	#~ if self.chunked:
	    # write last chunk and closing CRLF
	    #~ self.transport.write(b"0\r\n\r\n")

	# log request
	if hasattr(self.channel, "factory"):
	    self.channel.factory.log(self)
	    
	#~ if hasattr(self.channel, 'is_ssl_mode') and self.channel.is_ssl_mode:
	    #~ self.channel.transport.loseConnection()
	    #~ return
	
	self.finished = 1
	if not self.queued:
	    self._cleanup()
	


	
class LocalServer(HTTPChannel):
    requestFactory = ProxyRequest2
    is_ssl_mode = False
    
    def dataReceived(self, data):
	if self.is_ssl_mode and self.requests:
	    #~ log.msg('local server sent', len(data))
	    self.requests[-1].local_factory.after_conn.addCallback(lambda child: self.requests[-1].local_factory.child.send_encrypted(data))
	    self.requests[-1].local_factory.after_conn.addErrback(lambda reason: log.msg(reason))
	    return
	else:
	    HTTPChannel.dataReceived(self, data)
    
    #~ def connectionLost(self, reason):
	#~ if self.is_ssl_mode and self.requests:
	    #~ log.msg('local lost', self.requests[-1].local_factory.py_header)
	    #~ try:
		#~ self.requests[-1].local_factory.after_conn.addCallback(lambda local: self.requests[-1].local_factory.child.handle_close(source='here'))
		#~ #reactor.callLater(0, self.factory.pool.put, self.requests[-1].local_factory)
	    #~ except AttributeError:
		#~ log.msg('local lost WRONG')
	#~ else:
	    #~ HTTPChannel.connectionLost(self, reason)
	    
class LocalServerFactory(HTTPFactory):
    pool = TransferPool(LocalTransferFactory)
    protocol = LocalServer
    
class CloudTransfer(TransferContract):
    closed = 0
    has_header = False
    
    def parse_data(self, data):
	#~ log.msg('<-CT clean data:', len(data))
	if not self.has_header:
	    self.header = json.loads(data)
	    #~ log.msg('<-CT monitor:', self.header)
	    self.host = self.header['host']
	    port = self.header['port']
	    is_ssl = self.header['is_ssl']
	    if is_ssl:
		self.fetcher_factory = SslFetcherFactory(self)
	    else:
		self.fetcher_factory = HttpFetcherFactory(self)
	    reactor.connectTCP(self.host, port, self.fetcher_factory)
	    self.has_header = True
	else:
	    #~ log.msg('<-Cloud body data:', len(data))
	    #~ self.fetcher_factory.after_conn.addCallback(lambda child: (self.fetcher_factory.transfer(data), log.msg('cloud data sent', len(data))))
	    self.fetcher_factory.after_conn.addCallback(self.handle_after_conn, data)
	    self.fetcher_factory.after_conn.addErrback(lambda reason: log.msg(reason))
	    
	
    def handle_after_conn(self, ignore, data):
	self.fetcher_factory.transfer(data)
	#~ log.msg('->cloud data sent', len(data))
    
    def close(self):
	pass
	
    def update(self):
	self._trans_buff = ''
	self._trans_state = self.SIZE_STATE
	log.msg('Cloud Rewinded: ', self.header, self)
	return self
	
    def handle_remote_close(self):
	self.fetcher_factory.after_conn.addCallback(lambda child: self.fetcher_factory.child.transport.loseConnection())
    
    def handle_both_close(self):
	#~ self.body_size = 0
	self.verify_tag = ''
	self.here_closed = False
	self.remote_closed = False
	self.has_header = False
	#~ self._trans_buff = ''
	#~ self._trans_state = self.SIZE_STATE
	log.msg('Cloud Rewinded: ', self.header)
    
    def connectionLost(self, reason):
	self.closed = 1
	
    def write(self, data):
	self.send_encrypted(data)
	
class CloudTransferFactory(protocol.ServerFactory):
    pool = TransferPool(CloudTransfer)
    protocol = CloudTransfer
    #~ def buildProtocol(self, addr):
	#~ cloud_obj = self.pool.get()
	#~ cloud_obj.factory = self
	#~ return cloud_obj
	
class SslFetcher(Fetcher):
    def connectionMade(self):
	log.msg('Ssl Fetcher created')
	#finish modify send
	Fetcher.connectionMade(self)
	
    def connectionLost(self, reason):
	self.father.handle_close(source='here')

class SslFetcherFactory(FetcherFactory):
    protocol = SslFetcher	
    
class HttpFetcher(HTTPClient):
    
    def __init__(self, server, factory):
	log.msg('http init')
	self.server = server
	self.factory = factory
	self._finished = False
	self.malformed_content = False
	self.header_dict = {}
	
    def handleStatus(self, version, code, message):
	self.headers.append("%s %s %s"%(version, code, message))
	self.version = version
	self.code = code
	
    def extractHeader(self, header):
	#~ log.msg('header', repr(header))
	self.headers.append(header)
	HTTPClient.extractHeader(self, header)
	
    def handleHeader(self, key, val):
	self.header_dict[key.lower()] = val
	
    def handleEndHeaders(self):
	if ((self.version == b"HTTP/1.1") and
	    (self.header_dict.get(b'content-length', None) is None) and
	    (self.header_dict.get(b'transfer-encoding', None) is None) and
	    #~ self.method != b"HEAD" and self.code not in NO_BODY_CODES):
	    self.code not in ('204', '304')):
	    self.headers.append(b'transfer-encoding: chunked')
	    self.malformed_content = True

	self.headers.append('\r\n')
	#~ log.msg('-- header:', '\r\n'.join(self.headers))
	self.server.send_encrypted('\r\n'.join(self.headers))
	

    def handleResponseEnd(self):
	if not self._finished:
	    self._finished = True
	    if self.malformed_content:
		self.server.send_encrypted('\r\n0\r\n\r\n')
	    #~ log.msg('Handle End:', self.server.host)
	    log.msg('malformed?', self.malformed_content)
	    self.transport.loseConnection()
	    #~ self.server.transport.loseConnection()
	    self.server.handle_close(source='here')
	    
    def handleResponsePart(self, data):
	self.server.send_encrypted(data)
	
    def connectionMade(self):
	self.headers = []
	self.factory.after_conn.callback(self)
	HTTPClient.connectionMade(self)
    
    def send_data(self, data):
	#~ log.msg('http sent:', repr(data))
	self.transport.write(data)
	
    

class HttpFetcherFactory(FetcherFactory):
    protocol = HttpFetcher


log.startLogging(sys.stdout)
#~ log.startLogging(open('d:/foo.log', 'w'))
reactor.listenTCP(8083, CloudTransferFactory())
reactor.listenTCP(8090, LocalServerFactory())
reactor.run()
