from droidbot.device import Device
from droidbot.adapter.adb import ADB
from mitmproxy.io import FlowReader

import os
import hashlib
import argparse
import signal
import subprocess
import sys
import psutil
import time
import csv
from pathlib import Path

def install_app(apk, file_path, device_serial, adb_object):	
	print(f'Installing {apk}')	
	
	install_cmd = ["adb", "-s", device_serial, "install", "-r"]
	install_cmd.append("-g")
	install_cmd.append(file_path)
	install_p = subprocess.Popen(install_cmd, stdout=subprocess.PIPE)
	count = 0
	while apk not in adb_object.get_installed_apps():
		print("Please wait while installing the app...")
		count += 1
		time.sleep(2)

		if count >= 50:		
			with open(f'log_failed_{device_serial}.csv', 'a') as file:
				file.write(f'{apk}\n')
			return False

	return True

def uninstall_app(apk, device_serial, adb_object):  
	package_name = apk
	if package_name in adb_object.get_installed_apps():
		uninstall_cmd = ["adb", "-s", device_serial, "uninstall", package_name]
		uninstall_p = subprocess.Popen(uninstall_cmd, stdout=subprocess.PIPE)
		count = 0		
		while package_name in adb_object.get_installed_apps():
			print("Please wait while uninstalling the app...")
			count += 1
			time.sleep(2)

			if count >= 50:		
				break
		uninstall_p.terminate()

def is_mitm_running(listen_port):
	for proc in psutil.process_iter():
		try:
			cmd = ' '.join(proc.cmdline())
			mitm_cmd = f'--set block_global=false --set listen_port={listen_port}'
			if mitm_cmd in cmd:
				return True
		except Exception as e:			
			pass		
	return False


def start_monitor(out_dir_path, out_file_name, listen_port, device_serial, package_name):
	cmd_mitm = f'mitmdump -w {out_dir_path}/{out_file_name} --set block_global=false --set listen_port={listen_port}'
	pro_mitm = subprocess.Popen(cmd_mitm, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid) 													
	cmd_objection = f'objection -S {device_serial} -g {package_name} explore --startup-command "android sslpinning disable"'
	pro_objection = subprocess.Popen(cmd_objection, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)			

	return pro_mitm, pro_objection

def capture_screenshot(adb_object, out_dir_path):
	# try:		
	# 	shell_output = adb_object.shell(['uiautomator', 'dump'])		
	# 	shell_output = adb_object.run_cmd(['pull', '/sdcard/window_dump.xml', out_dir_path])				
	# except Exception as e:		
	# 	print(e)
	# 	pass
	try:	
		shell_output = adb_object.shell(['screencap', '-p', '/sdcard/screencap.png'])
		shell_output = adb_object.run_cmd(['pull', '/sdcard/screencap.png', out_dir_path])		
	except Exception as e:		
		print(e)
		pass

def tear_down(pro_mitm, pro_objection, listen_port):
	try:
		os.killpg(os.getpgid(pro_mitm.pid), signal.SIGKILL)							
	except Exception as e:		
		print(e)
		pass

	try:
		os.killpg(os.getpgid(pro_objection.pid), signal.SIGKILL)
	except Exception as e:		
		print(e)
		pass

	while is_mitm_running(listen_port):		
		for proc in psutil.process_iter():
			try:
				cmd = ' '.join(proc.cmdline())
				mitm_cmd = f'--set block_global=false --set listen_port={listen_port}'
				if mitm_cmd in cmd:
					proc.terminate()
					os.kill(proc.pid, 9)
					time.sleep(5)				
					break						
			except Exception as e:				
				pass	
		print('Waiting MITM!!!!!!!!!!!!')

def analyze_app(package_name, file_path, device_serial, listen_port, out_dir_path):	
	adb_object = ADB(Device(device_serial=device_serial))
	is_installed = install_app(package_name, file_path, device_serial, adb_object)
	if not is_installed:							
		return		
	time.sleep(8)

	out_file_name = os.path.basename(file_path)	
	Path(out_dir_path).mkdir(parents=True, exist_ok=True)

	#first time opening the app
	pro_mitm, pro_objection = start_monitor(out_dir_path, out_file_name + '_1', listen_port, device_serial, package_name)		
	time.sleep(15)
	capture_screenshot(adb_object, out_dir_path)			
	tear_down(pro_mitm, pro_objection, listen_port)
	adb_object.run_cmd(f'shell am force-stop {package_name}')	

	#second time opening the app
	pro_mitm, pro_objection = start_monitor(out_dir_path, out_file_name + '_2', listen_port, device_serial, package_name)		
	time.sleep(15)
	tear_down(pro_mitm, pro_objection, listen_port)	

	#uninstall the app
	uninstall_app(package_name, device_serial, adb_object)
	
def get_mitm_request_host(app_output_dir):		
	if not os.path.isdir(app_output_dir):
		return None
	
	requested_hostname_set = set()
	try:		
		for file in os.listdir(app_output_dir):
			if file.endswith('.apk_1') or file.endswith('.apk_2') or file.endswith('.apk_3'):
				with open(os.path.join(app_output_dir, file), 'rb') as fp:
					reader = FlowReader(fp)		
					for flow in reader.stream():			
						requested_hostname_set.add(flow.request.host)	
	except Exception as e:
		print(e)
		pass

	return requested_hostname_set	

def logging_error_app(package_name):
	with open(f'error_logging.csv', 'a') as file:
		file.write(f'{package_name}\n')

def get_apk_file_dict(csv_file):	
	apk_dict = dict()
	
	with open(csv_file,'r') as file:
		csv_reader = csv.reader(file)
		# skiping the header
		next(csv_reader, None)
		for row in csv_reader:
			apk_dict[row[0]] = row[1]	

	return apk_dict

def get_path(apk, home_dir):
	sha1 = hashlib.sha1()
	sha1.update(apk.encode('utf-8'))
	sha1String = sha1.hexdigest()

	file_path = os.path.join(home_dir, sha1String[0], sha1String[1], sha1String[2], sha1String[3], apk)	

	return file_path

def main():
	ap = argparse.ArgumentParser(description='Dynamic analysis to capture network transmission data')
	ap.add_argument('-s', '--serial', dest='serial', type=str)
	ap.add_argument('-p', '--port', dest='port', type=int)
	ap.add_argument('-f','--file', dest='file', type=str)	
	ap.add_argument('-o','--output', dest='output', type=str)
	args = ap.parse_args()			
	
	apk_file_dict = get_apk_file_dict(args.file)
	print(f'Total number of apps will be anazyed: {len(apk_file_dict)}')			
	
	for package_name in apk_file_dict:		
		apk_file_path = apk_file_dict[package_name]			
		if not os.path.exists(apk_file_path):			
			continue

		print(f'Starting running the: {package_name}')

		out_dir_path = get_path(package_name, args.output)	
		if os.path.isdir(out_dir_path):
			is_analyzed = False
			for file in os.listdir(out_dir_path):
				if file.endswith('.apk_1') or file.endswith('.apk_2'):
					tmp_set = get_mitm_request_host(out_dir_path)
					if tmp_set is not None and len(tmp_set) > 0:
						is_analyzed = True
					break
			if is_analyzed:
				print(f'{apk_file_dict} is analyzed!')
				continue	
		
		analyze_app(package_name, apk_file_path, args.serial, args.port, out_dir_path)			

if __name__ == '__main__':
	main()