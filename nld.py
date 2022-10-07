import requests
# python3 -m pip install requests[socks]
requests.packages.urllib3.disable_warnings()
import json
import time

class NetLineDancer(object):
	def __init__(self, server_ip):
		self.session = requests.Session()
		headers = {
			'Accept': 'application/json',
		}
		#proxies = {
		#	'http': 'socks5h://127.0.0.1:1080',
		#	'https': 'socks5h://127.0.0.1:1080',
		#}
		self.session.headers.update()
		#self.session.proxies = proxies
		self.server_ip = server_ip
		self.base_url = f'https://{self.server_ip}'
		self.load_credentials()
		return
	
	def load_credentials(self):
		'''
			keys = ['username','password']
		'''
		try:
			open('configuration.json','r')
		except:
			print('[E] Credentials not found')
		
		with open('configuration.json','r') as f:
			file_raw = f.read()
		credentials = json.loads(file_raw)
		self.un = credentials['credentials']['username']
		self.pw = credentials['credentials']['password']
		return
	
	def post(self, path, payload, params={}):
		url = f'{self.base_url}/{path}'
		_params = {
			'j_username': self.un,
			'j_password': self.pw,
		}
		for param_key in params:
			_params[param_key] = params[param_key]
		response = self.session.post(
			url,
			params=_params,
			json=payload,
			verify=False,
		)
		output = {
			'success': False,
			'result': '',
			'response': response,
		}
		if response.status_code == 200:
			output['success'] = True
			try:
				response_json = json.loads(
					response.text
				)
				output['result'] = response_json['result']
			except:
				print('[E] Could not parse JSON for HTTP POST')
				pass
		else:
			pass
		return output
	
	def get_method(self, method, params):
		payload = {
			'jsonrpc': '2.0',
			'method': method,
			'params': params,
			'id': 1,
		}
		output = self.post('rest', payload)
		return output
	
	def get_inventory_all(self):
		method = 'Inventory.search'
		params = {
			'network': ['Default'],
			'scheme': 'ipAddress',
			'query': '0.0.0.0/0',
			'pageData': {
				'offset': 0,
				'pageSize': 10000,
			},
			'sortColumn': 'hostname',
			'descending': False,
		}
		output = self.get_method(method, params)
		return output
	
	def get_inventory_device(self, network, ip):
		method = 'Networks.getManagedNetwork'
		params = {
			'network': network,
			'ipAddress': ip,
		}
		output = self.get_method(method, params)
		return output
	
	def get_managed_network_by_name(self, name):
		method = 'Networks.getManagedNetwork'
		params = {
			'networkName': name,
		}
		output = self.get_method(method, params)
		return output
	
	def get_managed_network_by_bridge(self, name):
		method = 'Networks.getManagedNetwork'
		params = {
			'bridgeName': name,
		}
		output = self.get_method(method, params)
		return output
	
	def get_managed_networks(self):
		method = 'Networks.getAllManagedNetworks'
		params = {}
		output = self.get_method(method, params)
		print(f'[I] Found {len(output["result"])} result/s')
		return output
	
	def get_managed_network_names(self):
		method = 'Networks.getManagedNetworkNames'
		params = {}
		output = self.get_method(method, params)
		print(f'[I] Found {len(output["result"])} result/s')
		return output
	
	def get_jumphost_by_network(self, name):
		method = 'Jumphost.getJumphostForNetwork'
		params = {
			'networkName': name,
		}
		output = self.get_method(method, params)
		return output
	
	def get_configuration_log(self, network, ip):
		method = 'Configuration.retrieveSnapshotChangeLog'
		params = {
			'network': network,
			'ipAddress': ip,
			'pageData': {
				'offset': 0,
				'pageSize': 10000,
			},
		}
		output = self.get_method(method, params)
		return output
	
	def get_configuration(self, network, ip, path, timestamp):
		method = 'Configuration.retrieveRevision'
		params = {
			'network': network,
			'ipAddress': ip,
			'configPath': path,
			'timestamp': timestamp,
		}
		output = self.get_method(method, params)
		return output
	
	def print_config(self, config):
		from base64 import b64decode as b
		config_join = ''.join(config.split('\r\n'))
		output = b(config_join)
		return output
	
	def get_credential_config(self, network, config_name):
		method = 'Credentials.getCredentialConfig'
		params = {
			'network': network,
			'configName': config_name,
		}
		output = self.get_method(method, params)
		return output
	
	def get_credential_set(self, network, config_name):
		method = 'Credentials.getCredentialSets'
		params = {
			'pageData': {
				'offset': 0,
				'pageSize': 10000,
			},
			'network': network,
			'configName': config_name,
			'ipOrCidr': null,
			'sortColumn': 'hostname',
			'descending': False,
		}
		output = self.get_method(method, params)
		return output
	
	def run_scheduler_now(self, job_data):
		method = 'Scheduler.runNow'
		params = {
			'jobData': job_data
		}
		output = self.get_method(method, params)
		return output
	
	def get_scheduler_job(self, job):
		method = 'Scheduler.getJob'
		params = {
			'jobId': job,
		}
		output = self.get_method(method, params)
		return output
	
	def get_scheduler_job_all(self):
		method = 'Scheduler.searchJobs'
		params = {
			'pageData': {
				'offset': 0,
				'pageSize': 10000,
				'total': 10000,
				'jobData': {
					
				}
			},
			'networks': ['0.0.0.0/0'],
			'sortColumn': 'hostname',
			'descending': False,
		}
		output = self.get_method(method, params)
		return output
	
	def get_plugin_detail(self, execution):
		method = 'Plugins.getExecutionDetails'
		params = {
			'executionId': execution,
		}
		output = self.get_method(method, params)
		return output
	
	def get_compliance_rule(self, rule):
		method = 'Compliance.getRuleSet'
		params = {
			'ruleSetId': rule,
		}
		output = self.get_method(method, params)
		return output
	
	def get_compliance_policy_all(self):
		method = 'Compliance.getPolicies'
		params = {
			'network': 'Default',
		}
		output = self.get_method(method, params)
		return output
	
	def get_compliance_policy(self, policy):
		method = 'Compliance.getPolicy'
		params = {
			'policyId': policy,
		}
		output = self.get_method(method, params)
		return output
	
	def get_compliance_violation_by_ip(self, network, ip):
		method = 'Compliance.getViolationsForDevice'
		params = {
			'network': network,
			'ipAddress': ip,
		}
		output = self.get_method(method, params)
		return output
	
	def get_compliance_violation_by_policy(self, policy):
		method = 'Compliance.getViolationsForPolicy'
		params = {
			'policyId': policy,
		}
		output = self.get_method(method, params)
		return output
	
	def get_telemetry_arp_table(self, ip):
		method = 'Telemetry.getArpTable'
		params = {
			'pageData': {
				'offset': 0,
				'pageSize': 10000,
			},
			'managedNetwork': 'Default',
			'ipAddress': ip,
			'sort': 'ipAddress',
			'descending': False,
		}
		output = self.get_method(method, params)
		return output
	
	def get_telemetry_arp_entries(self, ip, offset=0):
		method = 'Telemetry.getArpEntries'
		params = {
			'pageData': {
				'offset': offset,
				'pageSize': 10000,
			},
			'networkAddress': ip,
			'sort': 'ipAddress',
			'descending': False,
			'networks': ['Default'],
		}
		output = self.get_method(method, params)
		return output
	
	def get_telemetry_arp_entries_all(self):
		output = []
		offset=0
		r = n.get_telemetry_arp_entries('0.0.0.0/0',offset=offset)
		total = r['result']['total']
		page = r['result']['pageSize']
		output.extend(r['result']['arpEntries'])
		while len(output) < total:
			offset += page
			r = self.get_telemetry_arp_entries('0.0.0.0/0',offset=offset)
			output.extend(r['result']['arpEntries'])
		return output
	
	def get_telemetry_mac_table(self, ip):
		method = 'Telemetry.getMacTable'
		params = {
			'pageData': {
				'offset': 0,
				'pageSize': 10000,
			},
			'managedNetwork': 'Default',
			'ipAddress': ip,
			'sort': 'ipAddress',
			'descending': False,
		}
		output = self.get_method(method, params)
		return output
	
	def get_telemetry_neighbors(self, ip):
		method = 'Telemetry.getNeighbors'
		params = {
			'managedNetwork': 'Default',
			'ipAddress': ip,
		}
		output = self.get_method(method, params)
		return output
	
	def get_telemetry_port(self, host):
		method = 'Telemetry.findSwitchPort'
		params = {
			'host': host,
			'networks': ['Default'],
		}
		output = self.get_method(method, params)
		return output
	
	def get_terminal_token(self, ip):
		method = 'Security.createTemporaryAuthenticationToken'
		params = {
			'attributes': {
				'targetDevice': ip,
				'targetProtocol': 'SSH',
			}
		}
		output = self.get_method(method, params)
		return output
	
	def get_terminal_log(self, key, value):
		'''
			schemes = [
				'user',
				'session',
				'since',
				'network',
				'target',
				'client',
				'hostname',
				'text',
			]
		'''
		method = 'TermLogs.search'
		params = {
			'scheme': key,
			'query': value,
			'sortColumn': 'logId',
			'descending': False,
		}
		output = self.get_method(method, params)
		return output
	
	def get_bridge_all(self):
		method = 'Bridges.getAllBridges'
		params = {}
		output = self.get_method(method, params)
		return output
	
	def get_bridge(self, name):
		method = 'Bridges.getBridge'
		params = {
			'bridgeName': name,
		}
		output = self.get_method(method, params)
		return output


if __name__ == '__main__':
	server = 'nld01.domain.com'
	n = NetLineDancer(server)
	
	'''
	## Inventory retrieval
	r = n.get_inventory_all()
	if r['success']:
		print('[I] Successful inventory retrieval')
		total = r['result']['total']
		print(f'[I] Found {total} devices')
		devices = r['result']['devices']
	else:
		print('[W] Failed to retrieve inventory')
	# List all
	for x in devices:
		print(x['hostname'],'--',x['ipAddress'])
	'''
	
	'''
	## Config
	r = n.get_configuration('Default','## REDACTED ##','/running-config',1610654422000)
	c = n.print_config(r['result']['content'])
	'''
	
	## Scheduler needs work
	
	r = n.get_telemetry_port('router1')
	#
	print('[I] End')
