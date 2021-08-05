import os
import hashlib
import csv
import argparse
import zlib
import gzip
import json
import hashlib
import base64

from collections import Counter
from urllib import parse
from mitmproxy.http import HTTPFlow
from mitmproxy.io import FlowReader
from urllib.parse import unquote
from urllib.parse import parse_qs 
from droidbot.device import Device
from droidbot.app import App
from droidbot.adapter.adb import ADB
from xml.etree import ElementTree as ET

DEVICE_PII_DICT = {	
	'FA6AL0309062':{
		'EMAIL':'tin.nguyen@cispa.de',		
		'GSF':'you can use the Device ID app to get the Google Service Framework'}
}

GPS_DICT = {'GPS_1':{'xx.xxxxxxx','x.xxxxxxx'},
			'GPS_2':{'xx.xxxxxx','x.xxxxxx'},
			'GPS_3':{'xx.xxxxx','x.xxxxx'},
			'GPS_4':{'xx.xxxx','x.xxxx'}}

class TRAFFIC_LOG:
	def __init__(self, device_serial, package_name, file, request_header_dict, host, host_query_dict, raw_content, parsed_data):		
		self.device_serial = device_serial
		self.package_name = package_name
		self.file_name = file
		self.request_header = request_header_dict
		self.host_name = host
		self.request_query = host_query_dict
		self.decoded_request_body = parsed_data
		self.request_body = raw_content	

class TRAFFIC_LOG_PARAMETER:
	def __init__(self, package_name, device_serial, file_name, host_name, parameter_name, parameter_value):		
		self.package_name = package_name		
		self.device_serial = device_serial
		self.file_name = file_name
		self.host_name = host_name
		self.parameter_name = parameter_name
		self.parameter_value = parameter_value				

class DEVICE:
	def __init__(self, device_id):
		self.device_id = device_id

	def get_wifi_info(self):
		device_id = self.device_id
		wifi_info_dict = dict()
		adb_object = ADB(Device(device_id))
		output = adb_object.run_cmd(f'shell dumpsys wifi')
		for line in output.split('\n'):
			if line.startswith('mWifiInfo'):
				line = line.replace('mWifiInfo ','')
				line_list = line.split(',')
				for item in line_list:
					item_list = item.split(': ')				
					name = item_list[0].strip()
					value = item_list[1].strip()					
					if name in ['SSID','BSSID','MAC']:					
						wifi_info_dict[name] = value
				break
		return wifi_info_dict

	def get_advertising_id(self):
		device_id = self.device_id
		adid_list = []
		adb_object = ADB(Device(device_id))
		output = adb_object.run_cmd(f'shell su -c grep adid_key /data/data/com.google.android.gms/shared_prefs/adid_settings.xml')
		for line in output.split('\n'):
			root = ET.fromstring(line.strip())		
			if root.text is not None:
				adid_list.append(root.text)
		return adid_list

	# 1  getDeviceId
	# 2  getDeviceIdForSubscriber
	# 3  getImeiForSubscriber
	# 4  getDeviceSvn
	# 5  getSubscriberId
	# 6  getSubscriberIdForSubscriber
	# 7  getGroupIdLevel1
	# 8  getGroupIdLevel1ForSubscriber
	# 9  getIccSerialNumber
	# 10  getIccSerialNumberForSubscriber
	# 11  getLine1Number
	# 12  getLine1NumberForSubscriber
	# 13  getLine1AlphaTag
	# 14  getLine1AlphaTagForSubscriber
	# 15  getMsisdn
	# 16  getMsisdnForSubscriber
	# 17  getVoiceMailNumber
	# 18  getVoiceMailNumberForSubscriber
	# 19  getCompleteVoiceMailNumber
	# 20  getCompleteVoiceMailNumberForSubscriber
	# 21  getVoiceMailAlphaTag
	# 22  getVoiceMailAlphaTagForSubscriber
	# 23  getIsimImpi
	# 24  getIsimDomain
	# 25  getIsimImpu
	# 26  getIsimIst
	# 27  getIsimPcscf
	# 28  getIsimChallengeResponse
	# 29  getIccSimChallengeResponse
	def get_service_call(self, service_call_code):	
		device_id = self.device_id
		adb_object = ADB(Device(device_id))
		output = adb_object.run_cmd(f'shell su -c service call iphonesubinfo {service_call_code}')
		value_list = []
		for line in output.split('\n'):
			if '\'' not in line:
				continue
			data = line[line.index('\'')+1:line.rfind('\'')]
			for c in data:
				if c == '.':
					continue
				value_list.append(c)
		return ''.join(value_list).strip()

	def get_imei(self):
		device_id = self.device_id
		return self.get_service_call(1)

	def get_phone_number(self):
		device_id = self.device_id
		return self.get_service_call(12)

	def get_imsi(self):
		device_id = self.device_id
		return self.get_service_call(8)

	def get_line1Number(self):
		device_id = self.device_id
		return self.get_service_call(11)

	def get_installed_packages(self):
		device_id = self.device_id
		package_list = []
		adb_object = ADB(Device(device_id))
		output = adb_object.run_cmd('shell su -c cmd package list packages')
		for line in output.split('\n'):
			package_list.append(line.replace('package:','').strip())
		return package_list

	def get_contacts(self):
		device_id = self.device_id
		contact_list = []
		adb_object = ADB(Device(device_id))
		output = adb_object.run_cmd('shell su -c content query --uri content://contacts/phones/')
		for line in output.split('\n'):
			line_list = line.split(', ')
			contact_dict = dict()
			for item in line_list[1:-1]:
				item_list = item.split('=')
				contact_dict[item_list[0]]=item_list[1]
			contact_list.append(contact_dict)
		return contact_list	


def get_path(apk, home_dir):
	sha1 = hashlib.sha1()
	sha1.update(apk.encode('utf-8'))
	sha1String = sha1.hexdigest()

	file_path = os.path.join(home_dir, sha1String[0], sha1String[1], sha1String[2], sha1String[3], apk)	

	return file_path

def get_hash_values(value):
	hash_list = []
	text = str.encode(value)
	m = hashlib.sha1()
	m.update(text)
	hash_list.append(m.digest())
	hash_list.append(m.hexdigest())

	m = hashlib.sha224()
	m.update(text)
	hash_list.append(m.digest())
	hash_list.append(m.hexdigest())

	m = hashlib.sha256()
	m.update(text)
	hash_list.append(m.digest())
	hash_list.append(m.hexdigest())

	m = hashlib.sha384()
	m.update(text)
	hash_list.append(m.digest())
	hash_list.append(m.hexdigest())

	m = hashlib.sha512()
	m.update(text)
	hash_list.append(m.digest())
	hash_list.append(m.hexdigest())

	m = hashlib.blake2b()
	m.update(text)
	hash_list.append(m.digest())
	hash_list.append(m.hexdigest())

	m = hashlib.blake2s()
	m.update(text)
	hash_list.append(m.digest())
	hash_list.append(m.hexdigest())

	m = hashlib.md5()
	m.update(text)
	hash_list.append(m.digest())
	hash_list.append(m.hexdigest())

	encoded = base64.b64encode(text)
	hash_list.append(encoded)
	return hash_list

		

def detect_pii(traffic_log, hashed_pii_dict):	
	device_serial = traffic_log.device_serial
	pii_dict = hashed_pii_dict[device_serial]		
	requested_pii_set = set()

	combined_string = str(traffic_log.request_header)
	combined_string += str(traffic_log.request_query)
	combined_string += str(traffic_log.request_body)
	combined_string += str(traffic_log.decoded_request_body)	
	
	for key in pii_dict:			
		is_found = False
		for pii_value in pii_dict[key]:
			if pii_value in combined_string:										
				is_found = True				
				break
		if is_found:						
			requested_pii_set.add(key)
	return requested_pii_set

def detect_pii_parameter(log_parameter, hashed_pii_dict):	
	device_serial = log_parameter.device_serial
	pii_dict = hashed_pii_dict[device_serial]		
	requested_pii_set = set()

	combined_string = str(log_parameter.parameter_name)
	combined_string += str(log_parameter.parameter_value)

	try:
		base64decoded = base64.b64decode(log_parameter.parameter_value.encode())
		combined_string += str(base64decoded)
	except Exception as e:
		pass		
	
	for key in pii_dict:			
		is_found = False
		for pii_value in pii_dict[key]:
			if pii_value in combined_string:										
				is_found = True				
				break
		if is_found:						
			requested_pii_set.add(key)
	return requested_pii_set

def init_pii_dict(device_serial):
	# init device PII dict	
	device_object = DEVICE(device_serial)
	wifi_info_dict = device_object.get_wifi_info()
	for key in wifi_info_dict:
		DEVICE_PII_DICT[device_serial][key] = wifi_info_dict[key]

	DEVICE_PII_DICT[device_serial]['AID'] = device_object.get_advertising_id()[0]
	DEVICE_PII_DICT[device_serial]['IMEI'] = device_object.get_imei()
	DEVICE_PII_DICT[device_serial]['PHONE_NUMBER'] = device_object.get_phone_number()
	DEVICE_PII_DICT[device_serial]['SIM_SERIAL'] = device_object.get_line1Number()
	DEVICE_PII_DICT[device_serial]['IMSI'] = device_object.get_imsi()
	DEVICE_PII_DICT[device_serial]['SERIAL'] = device_serial
	
	
	hashed_pii_dict = dict()	
	pii_dict = DEVICE_PII_DICT[device_serial]	
	if device_serial not in hashed_pii_dict:
		hashed_pii_dict[device_serial] = dict()
	for key in pii_dict:				
		value = pii_dict[key]
		if value == '':
			continue			
		if key not in hashed_pii_dict[device_serial]:
			hashed_pii_dict[device_serial][key] = set()								

		# adding original string, and lower, and uper case
		hashed_pii_dict[device_serial][key].add(value)
		hashed_pii_dict[device_serial][key].add(value.lower())
		hashed_pii_dict[device_serial][key].add(value.upper())

		hashed_value_list = get_hash_values(value)
		hashed_value_list.extend(get_hash_values(value.lower()))
		hashed_value_list.extend(get_hash_values(value.upper()))

		for hashed_value in hashed_value_list:
			hashed_value = str(hashed_value)
			if hashed_value.startswith("b'") or hashed_value.startswith('b"'):
				hashed_value = hashed_value[2:-1]	
			if hashed_value != '':
				hashed_pii_dict[device_serial][key].add(hashed_value)
				hashed_pii_dict[device_serial][key].add(hashed_value.lower())
				hashed_pii_dict[device_serial][key].add(hashed_value.upper())

	for key in GPS_DICT:
		for value in GPS_DICT[key]:
			if value == '':
				continue			
			if key not in hashed_pii_dict[device_serial]:
				hashed_pii_dict[device_serial][key] = set()								

			hashed_pii_dict[device_serial][key].add(value)
			hashed_value_list = get_hash_values(value)
			for hashed_value in hashed_value_list:
				hashed_value = str(hashed_value)
				if hashed_value.startswith("b'") or hashed_value.startswith('b"'):
					hashed_value = hashed_value[2:-1]	
				if hashed_value != '':
					hashed_pii_dict[device_serial][key].add(hashed_value)
					hashed_pii_dict[device_serial][key].add(hashed_value.lower())
					hashed_pii_dict[device_serial][key].add(hashed_value.upper())
	return hashed_pii_dict

def get_apk_file_dict(csv_file):	
	apk_dict = dict()
	
	with open(csv_file,'r') as file:
		csv_reader = csv.reader(file)
		# skiping the header
		next(csv_reader, None)
		for row in csv_reader:
			apk_dict[row[0]] = row[1]	

	return apk_dict

def read_request_flow(file_path, device_serial, package_name, file):
	traffic_log_list = []			
	with open(file_path, 'rb') as fp:
		reader = FlowReader(fp)		
		for flow in reader.stream():
			if type(flow) is not HTTPFlow:
				continue					

			request_header_dict = dict()
			for key in flow.request.headers:
				request_header_dict[key] = flow.request.headers[key]				
			
			host_query_dict = dict()						
			for key in flow.request.query:				
				host_query_dict[key] = flow.request.query[key]
			
			if str(flow.request.raw_content) == "b''":
				continue
			try:
				request_dict = json.loads(flow.request.raw_content)								
				# print(f'{device_serial},{package_name},{file},{request_header_dict},{flow.request.host},{host_query_dict},{flow.request.raw_content},{request_dict}')						
				
				traffic_log_list.append(TRAFFIC_LOG(device_serial, package_name, file, json.dumps(request_header_dict), flow.request.host, json.dumps(host_query_dict), flow.request.raw_content, json.dumps(request_dict)))				

			except Exception as e:							
				try:					
					decoded_content = unquote(str(flow.request.content))						
					if decoded_content.startswith('b"') or decoded_content.startswith("b'"):
						decoded_content = decoded_content[2:-1]					
					try:
						parsed_data = parse_qs(decoded_content) 																			
						# print(f'{device_serial},{package_name},{file},{request_header_dict},{flow.request.host},{host_query_dict},{flow.request.raw_content},{parsed_data}')								
						
						traffic_log_list.append(TRAFFIC_LOG(device_serial, package_name, file, json.dumps(request_header_dict), flow.request.host, json.dumps(host_query_dict), flow.request.raw_content, json.dumps(parsed_data)))
					except Exception as e:						
						raise e1
				except Exception as e:					
					# print(f'{device_serial},{package_name},{file},{request_header_dict},{flow.request.host},{host_query_dict},{flow.request.raw_content},""')							
					
					traffic_log_list.append(TRAFFIC_LOG(device_serial, package_name, file, json.dumps(request_header_dict), flow.request.host, json.dumps(host_query_dict), flow.request.raw_content, json.dumps("")))
					pass
	return traffic_log_list

def recursive_insert(traffic_log_parameters, package_name, device_serial, file_name, host_name, data, prefix=''):			

	if isinstance(data, dict):				
		for key, value in data.items():
			db_key = (prefix + '.' + key).lstrip('.')			
			recursive_insert(traffic_log_parameters, package_name, device_serial, file_name, host_name, value, db_key)
		return

	if isinstance(data, list):		
		for item in data:			
			recursive_insert(traffic_log_parameters, package_name, device_serial, file_name, host_name, item, prefix)		
		return
					
	if isinstance(data, str):	
		if '\0' in data:
			data = data.replace('\0','replaced_null_code')								

		is_json_dict = False
		try:
			data = json.loads(data)
			is_json_dict = True
		except Exception as e:
			is_json_dict = False

		if is_json_dict:
			recursive_insert(traffic_log_parameters, package_name, device_serial, file_name, host_name, data, prefix)
			return	

		is_eval = False
		try:			
			data = eval(data)
			is_eval = True
		except Exception as e:
			is_eval = False

		if is_eval:
			recursive_insert(traffic_log_parameters, package_name, device_serial, file_name, host_name, data, prefix)
			return
			
		if host_name == 'www.facebook.com':
			if data.startswith('{"context"') or data.startswith('{"request"'):
				data = data + '"}}'
				if ':null}' in data:
					data = data.replace(':null}',':"null"}')
				recursive_insert(traffic_log_parameters, package_name, device_serial, file_name, host_name, eval(data), prefix)
			else:											
				traffic_log_parameters.append(TRAFFIC_LOG_PARAMETER(package_name, device_serial, file_name, host_name, prefix, str(data)))
			return	
		
		if 'rayjump.com' in host_name and prefix == 'data':
			parsed = parse_qs(data)			
			recursive_insert(traffic_log_parameters, package_name, device_serial, file_name, host_name, parsed, prefix)
			return

		if 'smartadserver.com' in host_name and (prefix == ' name' or prefix == 'name'):
			arrs = data.split('\\r\\n')
			for item in arrs:
				if 'jsonMessage' in item or 'Content-Length' in item:
					continue
				if item.startswith('{'):
					recursive_insert(traffic_log_parameters, package_name, device_serial, file_name, host_name, json.loads(item), prefix)
				if item.startswith('--'):
					traffic_log_parameters.append(TRAFFIC_LOG_PARAMETER(package_name, device_serial, file_name, host_name, prefix, str(item.strip('--'))))
			return

		if 'taboola.com' in host_name and (prefix=='fil'):
			arrs = data.split('}]"},{')					
			if len(arrs) == 2:				
				item_1 = arrs[0] + '}]'									
				item_1_dict = eval(item_1)[0]
				recursive_insert(traffic_log_parameters, package_name, device_serial, file_name, host_name, item_1_dict, prefix)
				
				item_2 = '{' + arrs[1] + '"}'						
				recursive_insert(traffic_log_parameters, package_name, device_serial, file_name, host_name, json.loads(item_2), prefix)
			return
		if 'taboola.com' in host_name and (prefix=='events'):
			item = data + '"}]'					
			item_dict = eval(item)[0]
			recursive_insert(traffic_log_parameters, package_name, device_serial, file_name, host_name, item_dict, prefix)
			return

		traffic_log_parameters.append(TRAFFIC_LOG_PARAMETER(package_name, device_serial, file_name, host_name, prefix, str(data)))
			
		return					

	traffic_log_parameters.append(TRAFFIC_LOG_PARAMETER(package_name, device_serial, file_name, host_name, prefix, str(data)))

def dump_db_traffic_logs(traffic_log):	
	try:		
		traffic_log_parameters = []

		device_serial = traffic_log.device_serial
		package_name = traffic_log.package_name 
		file_name = traffic_log.file_name
		request_header = traffic_log.request_header 
		host_name = traffic_log.host_name
		request_query = traffic_log.request_query 
		decoded_request_body = traffic_log.decoded_request_body 
		request_body = traffic_log.request_body	

		try:
			if '\\x' in decoded_request_body:				
				decoded_request_body = zlib.decompress(request_body, 16 + zlib.MAX_WBITS)										
		except Exception as e:			
			pass						

		try:		
			try:
				request_query_dict = json.loads(request_query)
			except Exception as e:
				request_query_dict = eval(request_query)
			recursive_insert(traffic_log_parameters, package_name, device_serial, file_name, host_name, request_query_dict)			
		except Exception as e:
			print(f'ERROR_REQUEST_QUERY:{id}:{request_query}')		
			
		is_dict_type = False
		try:	
			if 'flurry.com' in host_name and '\\\\x' in decoded_request_body:
				json_dict = reading_flurry_request_body(request_body)				
			elif 'ad-brix.com' in host_name:
				print(decoded_request_body)
			elif 'adincube.com' in host_name \
				or ('consoliads.com' in host_name and 'is_mac' in decoded_request_body) \
				or ('toponad.com' in host_name and decoded_request_body.startswith('{"{')):								
				json_dict = json.loads(decoded_request_body)			
				print(json_dict)
				try:
					key_str = list(json_dict.keys())[0]+'"}}'								
					key_json_dict = json.loads(key_str)									
				except Exception as e:
					key_str = list(json_dict.keys())[0]+'"}'								
					key_json_dict = json.loads(key_str)									

				value_str = str(list(json_dict.values())[0])		
				if value_str.startswith("['\","):
					value_str = value_str.replace("['\",","{\"temp\":{")
				if value_str.startswith("['=\","):
					value_str = value_str.replace("['=\",","{\"temp\":{")				
				value_str = value_str.rstrip("']")								
				
				try:					
					value_json_dict = json.loads(value_str)
				except Exception as e:
					try:
						value_json_dict = json.loads(value_str+'}')
					except Exception as e:
						value_json_dict = json.loads(value_str+'"}}')
					
				json_dict = dict()
				json_dict.update(key_json_dict)
				json_dict.update(value_json_dict)			
			else:				
				json_dict = json.loads(decoded_request_body)																	
			is_dict_type = True
		except Exception as e:
			try:
				json_dict = dict(decoded_request_body)				
				is_dict_type = True
			except Exception as e:				
				is_dict_type = False									
			
		if is_dict_type:			
			try:				
				recursive_insert(traffic_log_parameters, package_name, device_serial, file_name, host_name, json_dict)
			except Exception as e:						
				print(e)
		
	except Exception as e:						
		print(f'ERROR_SQL:{e}:{id}:{request_body}')

	return traffic_log_parameters

def main():
	ap = argparse.ArgumentParser(description='Detecting personal data in the network traffic by String-Matching Device-Bound Data')
	ap.add_argument('-s', '--serial', dest='serial', type=str)	
	ap.add_argument('-f','--file', dest='file', type=str)	
	ap.add_argument('-d','--log_dir', dest='log_dir', type=str)
	args = ap.parse_args()			
	
	apk_file_dict = get_apk_file_dict(args.file)
	print(f'Total number of apps will be anazyed: {len(apk_file_dict)}')			

	traffic_logs = []
	for package_name in apk_file_dict:			
		dir_path = get_path(package_name, args.log_dir)
		if not os.path.isdir(dir_path):
			continue			
		
		for file in os.listdir(dir_path):
			if not file.endswith('.apk_1') and not file.endswith('.apk_2'):				
				continue			
			
			file_path = os.path.join(dir_path, file)		
			traffic_logs.extend(read_request_flow(file_path, args.serial, package_name, file))
	

	hashed_pii_dict = init_pii_dict(args.serial)			

	analyzed_app_set = set()	
	dump_csv_line_set = set()
	for log in traffic_logs:						
		analyzed_app_set.add(log.package_name)		
		requested_pii_set = detect_pii(log, hashed_pii_dict)
		host_name_url = log.host_name
		if len(requested_pii_set) == 0:
			continue		
		for key in requested_pii_set:
			template_str = f'"{log.package_name}","{host_name_url}","{key}"'			
			dump_csv_line_set.add(template_str)

		traffic_parameters = dump_db_traffic_logs(log)	
		for log_parameter in traffic_parameters:	
			requested_pii_set = detect_pii_parameter(log_parameter, hashed_pii_dict)
			host_name_url = log_parameter.host_name
			if len(requested_pii_set) == 0:
				continue		
			for key in requested_pii_set:
				template_str = f'"{log_parameter.package_name}","{host_name_url}","{key}"'				
				dump_csv_line_set.add(template_str)	

	print(dump_csv_line_set)
	

if __name__ == '__main__':
	main()