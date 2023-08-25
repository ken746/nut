#!/usr/bin/python3
# -*- coding: utf-8 -*-
import json
import os
import time
import collections
from binascii import unhexlify as uhx
from nut import Print
from nut.config_impl.download import Download
from collections.abc import Mapping

threads = 1
jsonOutput = False
isRunning = True
dryRun = False
shardCount = None
shardIndex = None
reverse = False
extractVersion = False
autoUpdateTitleDb = True
allowNoMetadata = True
cdnCacheOnly = False

region = None

autolaunchBrowser = True

titleBlacklist = []
titleWhitelist = []

region = 'US'
language = 'en'

titleUrls = []
pullUrls = []
original = {}

g_regionLanguages = None

DEFAULT_REGION_LANGUAGES = '{"CO":["en","es"],"AR":["en","es"],"CL":["en","es"],\
	"PE":["en","es"],"KR":["ko"],"HK":["zh"],"CN":["zh"],"NZ":["en"],"AT":["de"],\
	"BE":["fr","nl"],"CZ":["en"],"DK":["en"],"ES":["es"],"FI":["en"],"GR":["en"],\
	"HU":["en"],"NL":["nl"],"NO":["en"],"PL":["en"],"PT":["pt"],"RU":["ru"],"ZA":["en"],\
	"SE":["en"],"MX":["en","es"],"IT":["it"],"CA":["en","fr"],"FR":["fr"],"DE":["de"],\
	"JP":["ja"],"AU":["en"],"GB":["en"],"US":["es", "en"]}'

def dict_merge(dct, merge_dct, add_keys=True):
	dct = dct.copy()
	if not add_keys:
		merge_dct = {
			k: merge_dct[k]
			for k in set(dct).intersection(set(merge_dct))
		}

	for k, _ in merge_dct.items():
		if (k in dct and isinstance(dct[k], dict)
				and isinstance(merge_dct[k], Mapping)):
			dct[k] = dict_merge(dct[k], merge_dct[k], add_keys=add_keys)
		else:
			dct[k] = merge_dct[k]

	return dct

def getGdriveCredentialsFile():
	files = ['credentials.json', 'conf/credentials.json']

	for file in files:
		if os.path.exists(file):
			return file

	return None

class Server:  # pylint: disable=too-few-public-methods
	"""Server-related settings
	"""

	def __init__(self):
		self.hostname = '0.0.0.0'
		self.port = 9000
		self.enableLocalDriveAccess = 1

class Compression:  # pylint: disable=too-few-public-methods
	"""Compression-related settings
	"""

	def __init__(self):
		self.level = 19
		self.auto = False

class Paths:  # pylint: disable=too-many-instance-attributes
	"""Paths-related settings
	"""

	def __init__(self):
		self.titleBase = 'zsw/{baseName}/{name} [{id}][v{version}].nsp'
		self.titleDLC = 'zsw/{baseName}/dlc/{name} [{id}][v{version}].nsp'
		self.titleUpdate = 'zsw/{baseName}/updates/{name} [{id}][v{version}].nsp'
		self.titleDemo = 'zsw/demos/{name} [{id}][v{version}].nsp'
		self.titleDemoUpdate = 'zsw/demos/updates/{name} [{id}][v{version}].nsp'

		self.nsxTitleBase = None
		self.nsxTitleDLC = None
		self.nsxTitleUpdate = None
		self.nsxTitleDemo = None
		self.nsxTitleDemoUpdate = None

		self.nszTitleBase = 'zsw/{baseName}/{name} [{id}][v{version}].nsz'
		self.nszTitleDLC = 'zsw/{baseName}/dlc/{name} [{id}][v{version}].nsz'
		self.nszTitleUpdate = 'zsw/{baseName}/updates/{name} [{id}][v{version}].nsz'
		self.nszTitleDemo = 'zsw/demos/{name} [{id}][v{version}].nsz'
		self.nszTitleDemoUpdate = 'zsw/demos/updates/{name} [{id}][v{version}].nsz'

		self.xciTitleBase = 'zsw/{baseName}/{name} [{id}][v{version}].xci'
		self.xciTitleDLC = 'zsw/{baseName}/dlc/{name} [{id}][v{version}].xci'
		self.xciTitleUpdate = 'zsw/{baseName}/updates/{name} [{id}][v{version}].xci'
		self.xciTitleDemo = 'zsw/demos/{name} [{id}][v{version}].xci'
		self.xciTitleDemoUpdate = 'zsw/demos/updates/{name} [{id}][v{version}].xci'

		self.xczTitleBase = 'zsw/{baseName}/{name} [{id}][v{version}].xcz'
		self.xczTitleDLC = 'zsw/{baseName}/dlc/{name} [{id}][v{version}].xcz'
		self.xczTitleUpdate = 'zsw/{baseName}/updates/{name} [{id}][v{version}].xcz'
		self.xczTitleDemo = 'zsw/demos/{name} [{id}][v{version}].xcz'
		self.xczTitleDemoUpdate = 'zsw/demos/updates/{name} [{id}][v{version}].xcz'		

		self.scan = ['NSW']
		self.titleDatabase = 'titledb'
		self.keys = 'keys.txt'
		self.calibration = 'PRODINFO.bin'
		self.shopNCert = 'ShopN.pem'
		self.nspOut = '_NSPOUT'
		self.titleImages = 'images/'

		self.duplicates = 'duplicates/'

	def mapping(self):
		m = {}

		if getGdriveCredentialsFile() is not None:
			m['gdrive'] = ''

		unknown = 0
		for f in self.scan:
			bits = f.split('#', 2)
			if len(bits) == 1:
				label = os.path.basename(f)
			else:
				label = bits[1]

			if not label or len(label) == 0 or label == '':
				label = 'L' + str(unknown)
				unknown += 1
			m[label] = bits[0]
		return m

	def getTitleBase(self, nsx, name):
		if not name:
			return None

		if nsx and (name.endswith('.nsp') or name.endswith('.nsx')):
			f = self.nsxTitleBase or self.titleBase
			return os.path.splitext(f)[0] + '.nsx'

		ext = name[-4:]
		f = None

		if ext == '.nsp':
			f = self.titleBase
		elif ext == '.nsz':
			f = getPath(self.nszTitleBase, name, self.titleBase)
		elif ext == '.nsx' and nsx:
			f = getPath(self.nsxTitleBase, name, self.titleBase)
		elif ext == '.xci':
			f = getPath(self.xciTitleBase, name, self.titleBase)
		elif ext == '.xcz':
			f = getPath(self.xczTitleBase, name, self.titleBase)
		if not f:
			f = self.titleBase
		return f

	def getTitleDLC(self, nsx, name):
		if not name:
			return None

		if nsx and (name.endswith('.nsp') or name.endswith('.nsx')):
			f = self.nsxTitleDLC or self.titleDLC
			return os.path.splitext(f)[0] + '.nsx'

		ext = name[-4:]
		f = None

		if ext == '.nsp':
			f = self.titleDLC
		elif ext == '.nsz':
			f = getPath(self.nszTitleDLC, name, self.titleDLC)
		elif ext == '.nsx' and nsx:
			f = getPath(self.nsxTitleDLC, name, self.titleDLC)
		elif ext == '.xci':
			f = getPath(self.xciTitleDLC, name, self.titleDLC)
		elif ext == '.xcz':
			f = getPath(self.xczTitleDLC, name, self.titleDLC)
		if not f:
			f = self.titleDLC
		return f

	def getTitleUpdate(self, nsx, name):
		if not name:
			return None

		if nsx and (name.endswith('.nsp') or name.endswith('.nsx')):
			f = self.nsxTitleUpdate or self.titleUpdate
			return forceExt(f, '.nsx')

		ext = name[-4:]
		f = None

		if ext == '.nsp':
			f = self.titleUpdate
		elif ext == '.nsz':
			f = getPath(self.nszTitleUpdate, name, self.titleUpdate)
		elif ext == '.nsx' and nsx:
			f = getPath(self.nsxTitleUpdate, name, self.titleUpdate)
		elif ext == '.xci':
			f = getPath(self.xciTitleUpdate, name, self.titleUpdate)
		elif ext == '.xcz':
			f = getPath(self.xczTitleUpdate, name, self.titleUpdate)
		if not f:
			f = self.titleUpdate
		return forceExt(f, ext)

	def getTitleDemo(self, nsx, name):
		if not name:
			return None

		if nsx and (name.endswith('.nsp') or name.endswith('.nsx')):
			f = self.nsxTitleDemo or self.titleDemo
			return os.path.splitext(f)[0] + '.nsx'

		ext = name[-4:]
		f = None

		if ext == '.nsp':
			f = self.titleDemo
		elif ext == '.nsz':
			f = getPath(self.nszTitleDemo, name, self.titleDemo)
		elif ext == '.nsx' and nsx:
			f = getPath(self.nsxTitleDemo, name, self.titleDemo)
		elif ext == '.xci':
			f = getPath(self.xciTitleDemo, name, self.titleDemo)
		elif ext == '.xcz':
			f = getPath(self.xczTitleDemo, name, self.titleDemo)
		if not f:
			f = self.titleDemo
		return f

	def getTitleDemoUpdate(self, nsx, name):
		if not name:
			return None

		if nsx and (name.endswith('.nsp') or name.endswith('.nsx')):
			f = self.nsxTitleDemoUpdate or self.titleDemoUpdate
			return os.path.splitext(f)[0] + '.nsx'

		ext = name[-4:]
		f = None

		if ext == '.nsp':
			f = self.titleDemoUpdate
		elif ext == '.nsz':
			f = getPath(self.nszTitleDemoUpdate, name, self.titleDemoUpdate)
		elif ext == '.nsx' and nsx:
			f = getPath(self.nsxTitleDemoUpdate, name, self.titleDemoUpdate)
		elif ext == '.xci':
			f = getPath(self.xciTitleDemoUpdate, name, self.titleDemoUpdate)
		elif ext == '.xcz':
			f = getPath(self.xczTitleDemoUpdate, name, self.titleDemoUpdate)
		if not f:
			f = self.titleDemoUpdate
		return f

def getPath(path, name, default):
	if not path:
		path = os.path.splitext(default)[0] + name[-4:]
		base = os.path.basename(path)
		path = os.path.join(os.path.dirname(path), name[-3:])
		path = os.path.join(path, base)
	return path

def forceExt(path, ext):
	return os.path.splitext(path)[0] + ext

def jset(json_, paths_, value):  # pylint: disable=redefined-builtin
	last = paths_.pop()
	for path in paths_:
		if path not in json_:
			json_[path] = {}
		json_ = json_[path]
	json_[last] = value

def save(confFile='conf/nut.conf'):
	return

def load(confFile):  # pylint: disable=too-many-branches,too-many-statements
	return

def update_scan_paths(new_scan_paths, nsp_files):
	"""Function update_paths is intended to update paths in the configuration file.
	NSPs will be cleared (in memory) if corresponding paths have been changed.

	Args:
					new_scan_paths (list of strings): list of strings (paths) to scan titles in
					nsp_files (map of strings): map of available (scanned) titles
	Returns:
					None
	"""
	path_changed = False

	new_scan_paths_ = new_scan_paths
	if not isinstance(new_scan_paths_, list):
		new_scan_paths_ = [new_scan_paths]

	old_paths = paths.scan

	if new_scan_paths_ != old_paths:
		path_changed = True

	if not path_changed:
		return

	paths.scan = new_scan_paths_
	save()

	if path_changed:
		nsp_files.clear()


def regionLanguages(fileName='titledb/languages.json'):
	global g_regionLanguages  # pylint: disable=global-statement

	if g_regionLanguages is not None:
		return g_regionLanguages

	g_regionLanguages = []

	try:
		with open(fileName, encoding='utf-8-sig') as f:
			g_regionLanguages = json.loads(f.read())
	except BaseException:  # pylint: disable=broad-except
		g_regionLanguages = json.loads(DEFAULT_REGION_LANGUAGES)

	return g_regionLanguages

def loadTitleWhitelist():
	global titleWhitelist  # pylint: disable=global-statement
	titleWhitelist = []
	try:
		with open('conf/whitelist.txt', encoding='utf8') as f:
			for line in f.readlines():
				titleWhitelist.append(line.strip().upper())
	except BaseException:  # pylint: disable=broad-except
		pass

def loadTitleBlacklist():
	global titleBlacklist  # pylint: disable=global-statement
	titleBlacklist = []

	confDir = 'conf'

	try:
		files = os.listdir(confDir)
	except FileNotFoundError:
		return

	for file in files:
		path = os.path.abspath(os.path.join(confDir, file))

		if 'blacklist' not in path:
			continue

		print(f"loading blacklist {path}")

		try:
			with open(path, encoding='utf8') as f:
				for line in f.readlines():
					id_ = line.split('|')[0].strip().upper()
					if id_:
						titleBlacklist.append(id_)
		except BaseException:  # pylint: disable=broad-except
			pass


compression = Compression()
paths = Paths()
server = Server()


class DAuthToken:
	"""DAuthToken
	"""

	def __init__(self, clientId):
		self.token = None
		self.expires = None
		self.clientId = clientId

	def fileName(self):
		return f"dauth.{self.clientId}.token"

	def get(self):
		if not self.token:
			try:
				with open(self.fileName(), encoding='utf8') as f:
					self.token = f.read().strip()
					self.expires = os.path.getmtime(self.fileName()) + (60 * 60)
			except BaseException as e:  # pylint: disable=broad-except
				Print.error(str(e))  # pylint: disable=undefined-variable

		if not self.token or not self.expires or time.time() > self.expires:
			import cdn.Auth  # pylint: disable=import-outside-toplevel,redefined-outer-name,import-error
			self.token = cdn.Auth.getDauthToken(self.clientId)
			self.expires = os.path.getmtime(self.fileName()) + (60 * 60)

		if not self.token:
			raise IOError('No dauth token')

		return self.token

class Proxies:  # pylint: disable=too-few-public-methods
	"""Proxies-related settings
	"""

	def __init__(self):
		self.http = None  # 'socks5://192.169.156.211:45578'
		self.https = None  # 'socks5://192.169.156.211:45578'

	def get(self):
		m = {}
		if self.http:
			m['http'] = self.http

		if self.https:
			m['https'] = self.https

		if len(m) == 0:
			return None

		return m

class Cdn:  # pylint: disable=too-few-public-methods
	"""Cdn
	"""

	def __init__(self):
		self.region = 'US'
		self.firmware = None
		self.deviceId = None
		self.environment = 'lp1'
		self.clientIds = { "eShop": "93af0acb26258de9", "atumC1": "3117b250cab38f45", "tigers": "d5b6cac2c1514c56", "tagaya": "41f4a6491028e3c4"}

	def getDeviceId(self):
		if not self.deviceId:
			raise IOError('device id not set')

		bytes_ = uhx(self.deviceId)

		if len(bytes_) < 7:
			raise IOError('device id too small')

		if len(bytes_) > 8:
			raise IOError('device id too large')

		if int.from_bytes(bytes_, byteorder='big') < 0x100000000000:
			raise IOError('device id incorrect')

		return self.deviceId.lower()

class EdgeToken:
	"""EdgeToken
	"""

	def __init__(self, clientId):
		self.token = None
		self.expires = None
		self.clientId = clientId

	def fileName(self):
		return f"edge.{self.clientId}.token"

	def get(self):
		if not self.token:
			try:
				with open(self.fileName(), encoding='utf8') as f:
					self.token = f.read().strip()
					self.expires = os.path.getmtime(self.fileName()) + (60 * 60)
			except BaseException as e:  # pylint: disable=broad-except
				Print.error(str(e))  # pylint: disable=undefined-variable

		if not self.token or not self.expires or time.time() > self.expires:
			import cdn.Auth  # pylint: disable=redefined-outer-name,import-outside-toplevel,import-error
			self.token = cdn.Auth.getEdgeToken(self.clientId)
			self.expires = os.path.getmtime(self.fileName()) + (60 * 60)

		if not self.token:
			raise IOError('No edge token')

		return self.token

class DAuth:  # pylint: disable=too-few-public-methods
	"""DAuth
	"""

	def __init__(self):
		self.keyGeneration = None
		self.userAgent = None
		self.challenge = None
		self.sysDigest = None
		self.baseURL = None


cdn = Cdn()
download = Download()
proxies = Proxies()
dauth = DAuth()

if os.path.isfile('conf/nut.default.conf'):
	load('conf/nut.default.conf')

if os.path.isfile('conf/nut.conf'):
	load('conf/nut.conf')

loadTitleWhitelist()
loadTitleBlacklist()

try:
	edgeToken = EdgeToken(cdn.clientIds['tagaya'])
	c1EdgeToken = EdgeToken(cdn.clientIds['atumC1'])
	dauthToken = DAuthToken(cdn.clientIds['eShop'])
	dauthTigersToken = DAuthToken(cdn.clientIds['tigers'])
	eShopEdgeToken = EdgeToken(cdn.clientIds['eShop'])
except BaseException:  # pylint: disable=broad-except
	pass

try:
	os.mkdir(paths.nspOut)
except BaseException:  # pylint: disable=broad-except
	pass

try:
	os.mkdir(paths.titleImages)
except BaseException:  # pylint: disable=broad-except
	pass
