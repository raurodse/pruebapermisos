import netifaces
import netaddr
import socket
import struct
import subprocess

def is_valid_ip(ip):
	'''
	Checks whether an ip is valid or not.
	Returns True or False.
	ex:
		is_valid_ip("10.0.0.160")
	'''
	if ip=="" or ip==None:
		return False
	
	return netaddr.valid_ipv4(ip)

		
#def is_valid_ip


def is_ip_in_range(ip,ip_network):
	'''
	Checks whether an ip is a child of a certain network.
	Returns True or False.
	ex:
		is_ip_in_range("10.0.0.160","10.0.0.128/25")
	'''
	#ip_network ex: "10.0.0.128/24"
	try:
		return netaddr.ip.IPAddress(ip) in netaddr.IPNetwork(ip_network).iter_hosts()
	except Exception:
		return False
	
#def is_ip_in_range


def get_ip_from_mac(mac):
	'''
	Returns ip from a mac. If the mac is not found, it returns None.
	'''
	for item in netifaces.interfaces():
		info=netifaces.ifaddresses(item)
		try:
			if info[netifaces.AF_LINK][0]["addr"]==mac:
				return info[netifaces.AF_INET][0]["addr"]
		except Exception as e:
			print(e)
			
	return None
	
#def get_ip_from_mac


def get_ip_from_host(host):
	'''
	Resolves name from host. If it fails, it returns None
	'''
	try:
		return socket.gethostbyname(host)
	except Exception: 
		return None
	
#def get_ip_from_host


def get_mac_from_ip(ip):
	'''
	Returns mac from a certain ip. If the ip is not found, it returns None.
	'''
	
	for item in netifaces.interfaces():
		info=netifaces.ifaddresses(item)
		try:
			if info[netifaces.AF_INET][0]["addr"]==ip:
				return info[netifaces.AF_LINK][0]["addr"]
		except Exception as e:
			print(e)
	
#def get_mac_from_ip

def get_broadcast(dev):
	'''
	Returns broadcast value from a certain network interface. It returns None on failure.
	ex:
		get_broadcast("eth0")
	'''
	
	try:
		info=get_device_info(dev)
		return info["broadcast"]
	except Exception:
		return None
	
#def get_broadcast

def get_netmask(dev):
	'''
	Returns netmask value from a certain network interface. It returns None on failure.
	ex:
		get_netmask("eth0")
	'''	
	try:
		info=get_device_info(dev)
		return info["netmask"]
	except:
		return None
	
#def get_netmask

def get_bitmask(dev):
	'''
	Returns bitmask value from a certain network interface. It returns None on failure.
	ex:
		get_bitmask("eth0")
	'''	
	try:
		info=get_device_info(dev)
		return info["bitmask"]
	except:
		return None
	
#def get_bitmask

def get_ip(dev):
	'''
	Returns ip value from a certain network interface. It returns None on failure.
	ex:
		get_ip("eth0")
	'''	
	try:
		info=get_device_info(dev)
		return info["ip"]
	except:
		return None
	
#def get_ip


def get_device_info(dev):
	'''
	Returns a dictionary with the information of a certain network interface.
	ex:
		get_device_info("eth0")
	'''	
	dic={}
	for item in netifaces.interfaces():
		if item==dev:
			p = subprocess.Popen(['/sbin/ethtool',item],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
			status = p.wait()
			aux_lines = [ y.strip() for y in p.stdout.readlines()]
			dic = {}
			if (status == 0):
				aux_lines.pop(0)
				for line in aux_lines:
					if type(line)!=type(''):
						line=line.decode()
					try:
						key,value = [x.strip() for x in line.split(':')]
						dic[key]=[]
						dic[key].append(value)
					except Exception as e:
						dic[key].append(line)

			info=netifaces.ifaddresses(item)
			dic["name"]=item

			if netifaces.AF_LINK in info.keys():
			
				if "addr" in info[netifaces.AF_LINK][0].keys():
					dic["mac"]=info[netifaces.AF_LINK][0]["addr"]
				else:
					dic["mac"]=""
			if netifaces.AF_INET in info.keys():
				if "broadcast" in info[netifaces.AF_INET][0].keys():
					dic["broadcast"]=info[netifaces.AF_INET][0]["broadcast"]
				else:
					dic["broadcast"]=""
				if "netmask" in info[netifaces.AF_INET][0].keys():
					dic["netmask"]=info[netifaces.AF_INET][0]["netmask"]
					dic["bitmask"]=get_net_size(dic["netmask"])
				else:
					dic["bitmask"]=""
					dic["netmask"]=""
				if "addr" in info[netifaces.AF_INET][0].keys():
					dic["ip"]=info[netifaces.AF_INET][0]["addr"]
				else:
					dic["ip"]=""
			
	return dic
	
#def get_device_info


def get_devices_info():
	'''
	Returns a list of dictionaries with the information of every network interface found in the system.
	'''	
	ret=[]
	for item in netifaces.interfaces():
		if item!="lo":
			ret.append(get_device_info(item))
	return ret
	
#def get_device_info


def get_net_size(netmask):
	'''
	Calculates bitmask from netmask
	ex:
		get_broadcast("eth0")
	'''
	netmask=netmask.split(".")
	binary_str = ''
	for octet in netmask:
		binary_str += bin(int(octet))[2:].zfill(8)
	return str(len(binary_str.rstrip('0')))

#def get_net_size


def get_default_gateway():
	'''
	Returns default gateway. 
	'''
	with open("/proc/net/route") as fh:
		count=0
		for line in fh:
			fields = line.strip().split()
			if fields[1] != '00000000' or not int(fields[3], 16) & 2:
				continue

			return count,socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
			
	return None
			
#def get_default_gateway			

def get_network_ip(ip,netmask):
	netmask = netmask.split(".")
	ip = ip.split(".")
	result = []
	for i in range(0,len(netmask)):
		x = str(int(bin(int(ip[i])&int(netmask[i])),2))
		result.append(x)
	return ".".join(result)


def change_option_sysctl(file_path,needle,value):
	if (os.path.exists(file_path)):
			f = open(file_path,'r')
			lines = f.readlines()
			f.close()
	else:
			lines = []
	found = False
	f = open(file_path,'w')
	for x in lines:
			if(needle in x): 
					f.write(value+"\n")
					found = True
					continue
			f.write(x)
	if (not found):
			f.write(value+"\n")
	f.close()



if __name__=="__main__":
	print(get_network_ip('192.168.254.245','255.255.255.0'))
	print(get_ip_from_mac('40:16:7e:17:e7:72'))
