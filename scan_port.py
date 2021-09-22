import nmap
import datetime
import os
import json
import multiprocessing 
from ifconfigparser import IfconfigParser
from netaddr import IPNetwork
import logging
from logging.handlers import RotatingFileHandler

g_tmp_json_file = "open_port.json"
g_masscan_args = "-p 1-10000 --rate 20000"

g_nmap_args = "-v -O"
g_nic = "wlp2s0"
g_process_num = multiprocessing.cpu_count()
g_task_id_pathname = "/data/nettraffic/etc/taskid"
g_logger = ''

tored = lambda s: "\033[1;31m%s\033[0m" % s
togreen = lambda s: "\033[1;32m%s\033[0m" % s

class InitLog(object):

	def __init__(self, log_name, log_path):
		self.logger = logging.getLogger(log_name)
		self.logger.setLevel(logging.DEBUG)

		rHandler = RotatingFileHandler(log_path, maxBytes=1 * 1024 * 1024, backupCount=3)
		rHandler.setLevel(logging.DEBUG)
		formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
		rHandler.setFormatter(formatter)

		# StreamHandler
		stream_handler = logging.StreamHandler(sys.stdout)
		stream_handler.setLevel(logging.DEBUG)

		self.logger.addHandler(stream_handler)
		self.logger.addHandler(rHandler)


def getTaskId():
	f = open(g_task_id_pathname, "r")
	line = f.readline()
	task_id = line.rstrip("\n").rstrip("\r\n")

	return int(task_id)
	


def getVlan(nic):
	r=os.popen("ifconfig")
	output = r.read()
	interfaces=IfconfigParser(console_output=output)
	local_ip = interfaces.get_interface(name=nic).ipv4_addr
	mask = interfaces.get_interface(name=nic).ipv4_mask

	vlan = str(IPNetwork("%s/%s" % (local_ip,mask)).cidr)

	return vlan

def timer(function):

	def wrapper(*args, **kwargs):
		g_logger.info("[%s] start" % function.__name__)
		#p = "[%s] start" % function.__name__
		print(togreen(p))
		begin_time = datetime.datetime.now()
		res = function(*args, **kwargs)
		end_time = datetime.datetime.now()
		run_time = "[%s] run time: [%s]s" % (function.__name__,(end_time-begin_time).seconds)
		print(togreen(run_time))
		return res

	return wrapper

@timer
def scanPort(vlan):

	g_masscan_cmd="/root/masscan/bin/masscan %s %s -oJ %s" % (vlan, g_masscan_args,g_tmp_json_file)
	g_logger.info(g_masscan_cmd)
	os.system(g_masscan_cmd)
	
@timer
def loadTmpJson():

	ip_info_dict = {}
	if os.path.exists(g_tmp_json_file):
		with open(g_tmp_json_file, "r") as f:
			for line in f:
				if line.startswith("{"):
					tmp_dict = {}
					
					tmp_info_dict = json.loads(line)

					ip = tmp_info_dict["ip"]
					ports_info_dict = tmp_info_dict["ports"][0]
					tmp_dict["timestamp"] = tmp_info_dict["timestamp"]
					tmp_dict["port"] = ports_info_dict["port"]
					tmp_dict["proto"] = ports_info_dict["proto"]
					if ip not in ip_info_dict:
						ip_info_dict[ip] = []
				
					ip_info_dict[ip].append(tmp_dict)
	else:
		g_logger.info(tored("masscan scan not find open port!"))
		#print(tored("masscan scan not find open port!"))

	print(ip_info_dict)

	return ip_info_dict


def parsePort(ip, port_info_list, share_write_json_list, share_lock, task_id):

	
	port_list = []
	for d in port_info_list:
		port_list.append(str(d["port"]))

	port_str = ",".join(port_list)

	nm = nmap.PortScanner()
	
	ret = nm.scan(hosts=ip,ports="%s" % port_str,arguments="%s" % g_nmap_args) 

	#for host in nm.all_hosts():
	nmap_ip_info = nm[ip]
	print(ip,nmap_ip_info.hostname(),nmap_ip_info.state())
	print(nmap_ip_info)
	#print(nm.csv())

	if nmap_ip_info.state() == "up":

		my_port_list = []

		for proto in nmap_ip_info.all_protocols():
			for port in nmap_ip_info[proto].keys():
				if nmap_ip_info[proto][port]["state"] == "open":
					my_port_dict = {}
					my_port_dict["port"] = port
					my_port_dict["server"] = nmap_ip_info[proto][port]["name"]
					my_port_dict["version"] = nmap_ip_info[proto][port]["version"]
					my_port_dict["protocol"] = proto
					my_port_list.append(my_port_dict)

		if my_port_list:
			my_ip_dict = {}
			my_ip_dict["ip"] = ip
			my_ip_dict["mac"] = nmap_ip_info["addresses"]["mac"]
			my_ip_dict["discoveryTime"] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			my_ip_dict["os"] = nmap_ip_info["osmatch"][0]["name"]
			my_ip_dict["osVersion"] = ""
			my_ip_dict["taskId"] = task_id
			my_ip_dict["ports"] = my_port_list

			share_lock.acquire()
			share_write_json_list.append(my_ip_dict)
			share_lock.release()



@timer
def mutilProcessRun(ip_info_dict, task_id):

	share_write_json_list = multiprocessing.Manager().list()
	share_lock = multiprocessing.Manager().Lock()

	#print("cpu num: %d" % multiprocessing.cpu_count())
	g_logger.info("cpu num: %d" % multiprocessing.cpu_count())
	pool = multiprocessing.Pool(processes=g_process_num)
	for ip, port_info_list in ip_info_dict.items():

		pool.apply_async(parsePort, (ip, port_info_list,share_write_json_list, share_lock, task_id, ))

	pool.close()
	pool.join()

	print(share_write_json_list)

	return share_write_json_list

@timer
def writeJsonFile(share_write_json_list):

	now_time = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
	json_file = "/opt/data/asset/%s.json" % now_time
	g_logger.info(json_file)
	#print(json_file)
	with open(json_file, "w") as f:
		json.dump(list(share_write_json_list), f)

@timer
def main():

	logger_name = "scan_port"
	log_pathname = os.path.join(g_log_path, "%s.log" % logger_name)
	il = InitLog(logger_name, log_pathname)

	g_logger = logging.getLogger(logger_name)

	valn = getVlan(g_nic)
	task_id = getTaskId()
	scanPort(valn)
	ip_info_dict = loadTmpJson()
	share_write_json_list = mutilProcessRun(ip_info_dict, task_id)
	writeJsonFile(share_write_json_list)



if __name__ == '__main__':
	main()
