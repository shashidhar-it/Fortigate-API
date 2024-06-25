from fortigate_api import FortigateAPI # use only V 1.2.5
from fortigate_api import Fortigate
from rich import print as rprint
import os,sys,ipaddress,yaml,re,time,requests,logging
from datetime import datetime
from functools import wraps

# Decorator Function to keep track in the log file
def log_function_call(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger = logging.getLogger(f"MLFortinetAPI_{args[0].Ipaddress}")
        function_name = func.__name__
        logger.info(f"Start {function_name}")
        try:
            result = func(*args, **kwargs)
            logger.info(f"End {function_name}")
            return result
        except Exception as e:
            logger.error(f"Error in {function_name}: {e}")
            raise
    return wrapper
    
class MLFortinetAPI(Fortigate, FortigateAPI):
    def __init__(self, Ipaddress):
        self.Ipaddress = Ipaddress
        passwd="password"
        self.logger = self._configure_logger()
        self.fgt1 = Fortigate(host=Ipaddress, username="admin", password=passwd, port=443)
        self.fgt = FortigateAPI(host=Ipaddress, username="admin", password=passwd, port=443)
        self.payload={'username': 'admin','secretkey': passwd}
        
    def _configure_logger(self):
        logger = logging.getLogger(f"MLFortinetAPI_{self.Ipaddress}")
        logger.setLevel(logging.DEBUG)
        
        logs_folder = "Logs"
        if not os.path.exists(logs_folder):
            os.makedirs(logs_folder)

        # Set up the file handler
        log_file_path = f"{logs_folder}/{self.Ipaddress}.log"
        file_handler = logging.FileHandler(log_file_path, mode='w')
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s:%(levelname)s:%(message)s")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        return logger
    
    @log_function_call
    def get_cpu_data(self: object) -> dict[str, str]:
        """
        Retrieve CPU usage information of Fortigate.
        Returns: Dict[str, str]: A dictionary containing CPU usage 
        information for user, system, nice, idle, and iowait.
        """
        print(f"Checking CPU Usage on {self.Ipaddress}")
        cpu_data = {}
        metrics = ['user', 'system', 'nice', 'idle', 'iowait']
        CPU = self.fgt1.get(url="/api/v2/monitor/system/performance/status")
        self.logger.debug(CPU)
        # Populate the dictionary with CPU metrics
        cpu_data['user'] = str(CPU['cpu']['user']) + "%"
        cpu_data['system'] = str(CPU['cpu']['system']) + "%"
        cpu_data['nice'] = str(CPU['cpu']['nice']) + "%"
        cpu_data['idle'] = str(CPU['cpu']['idle']) + "%"
        cpu_data['iowait'] = str(CPU['cpu']['iowait']) + "%"
        return cpu_data
        
    @log_function_call
    def get_memory_usage(self: object) -> list[str]:
        """Retrieve memory usage information of a Fortinet device.
        Returns:
        list[str]: A list containing memory usage information for used, free, and freeable memory percentages.
        The list follows the format [used_percentage, free_percentage, freeable_percentage].
        """
        print(f"Checking Memory Usage on {self.Ipaddress}")
        Values = []
        heading = ["used", 'free', 'freeable']
        Mem = self.fgt1.get(url="/api/v2/monitor/system/performance/status")
        self.logger.debug(Mem)
        total = Mem['mem']['total']
        Values.append(str(round(Mem['mem']['used'] / total * 100, 2)) + "%")
        Values.append(str(round(Mem['mem']['free'] / total * 100, 2)) + "%")
        Values.append(str(round(Mem['mem']['freeable'] / total * 100, 2)) + "%")
        Finallist = [item for pair in zip(heading, Values) for item in pair]
        return Finallist
        
    @log_function_call
    def get_dns(self: object) -> dict:
        """
        Retrieve standard DNS configuration information from a Fortinet device.
        Returns:
            dict: A dictionary containing standard DNS configuration information.
            The dictionary has the format { "Primary DNS": primary_dns_value, 
            "Secondary DNS": secondary_dns_value }.
            If no DNS configuration is found, an empty dictionary is returned.
        """
        print("Checking Standard DNS")
        dns_config = {}
        try:
            # Retrieve DNS configuration from the Fortinet device
            DNS = self.fgt1.get(url="/api/v2/cmdb/system/dns/")
            self.logger.debug(DNS)
            # Check if DNS configuration is available
            if len(DNS) > 0:
                dns_config["Primary DNS"] = DNS['primary']
                dns_config["Secondary DNS"] = DNS['secondary']
            else:
                self.logger.warning("No DNS configuration found.")
                print("No DNS configuration found.")
            return dns_config
        except Exception as e:
            self.logger.error(e)
            

        
    @log_function_call    
    def get_healthcheck(self: object)-> list:
        """
        Perform a health check on SD-WAN (Software-Defined Wide Area Network) configurations.
        This function queries a Fortinet device (fgt1) for SD-WAN health-check information
        and compiles the results into a list containing the names and server information.
        Returns:
            list: A list of lists representing SD-WAN health-check data. Each inner list
                  contains column headers ['name', 'server'] and corresponding values.
        """
        print("Checking SLA")
        HC=self.fgt1.get(url="/api/v2/cmdb/system/sdwan/health-check/")
        SLA_List=[]
        column_header=["name","server"]
        SLA_List.append(column_header)
        for i in range(len(HC)):
            eachHC=[]
            eachHC.append(str(HC[i]['name']))
            try:
                eachHC.append(str(HC[i]['server']))
            except:
                eachHC.append("Not Configured")
            SLA_List.append(eachHC)
        self.logger.debug(SLA_List)
        return SLA_List

    @log_function_call
    def get_sdwanzone(self: object) -> list:
        """
        Retrieve SD-WAN zone information from a Fortinet device.
        This function queries a Fortinet device (fgt1) for SD-WAN zone details and
        returns a list containing interface and zone information for each member.
        
        Returns:
            list: A list of strings representing SD-WAN zone information. Each pair
                of elements in the list corresponds to interface and zone values.
        """
        print("Checking SDWAN Zones")  
        result = []
        sdwan = self.fgt1.get(url="/api/v2/cmdb/system/sdwan/")
        data =sdwan['members']
        for member in data:
            result.append(member['interface'])
            result.append(member['zone'])
        self.logger.debug(result)
        return(result)

    @log_function_call
    def get_fgt_details(self: object)-> list:
        """_summary_

        Args:
            self (object): fortigateAPI object

        Returns:
            list: containing serial number , Version , Hostname
        """        
        login_url = f'https://{self.Ipaddress}:443/logincheck'
        login_response = requests.post(login_url, data=self.payload, verify=False)
        api_endpoint = f'https://{self.Ipaddress}:443/api/v2/cmdb/system/global'
        response = requests.get(api_endpoint, cookies=login_response.cookies, verify=False)
        data = response.json()
        res=[]
        res.append("Serial Number")
        res.append(data.get('serial'))
        res.append("Version")
        res.append(data.get('version') +" build "+ str(data.get('build')))
      
        hostname=self.fgt1.get(url="/api/v2/cmdb/system/global")

        res.append(hostname['hostname'])
        
        self.logger.debug(res)
        

    
    @log_function_call
    def get_fmg_status(self: object)->list:
        """_summary_

        Args:
            self (object): Takes fgt as a object

        Returns:
            list: of Fortimanager IP and Registration via Loopback details
        """
        print("Checking Fortimanager Settings")
        out=[]
        out.append("Fortimanager IP")
        
        FMG=self.fgt1.get(url="/api/v2/cmdb/system/central-management/")
        fmg_ip_cfgd=FMG['fmg'].strip('"')
        
        if fmg_ip_cfgd=="":
            out.append("Not Configured")
        else:
            out.append(fmg_ip_cfgd)
        
        out.append("Registered via Loopback")
        
        registered_via=FMG['fmg-source-ip']
            
        if(registered_via==self.Ipaddress):
            out.append("Yes")
        else:
            out.append("No")
        self.logger.debug(out)
        return out
    
    @log_function_call
    def get_analyzer_status(self: object,faz_ip)->list:
        """_summary_

        Args:
            self (object): Takes fgt as a object

        Returns:
            list: of fortiAnalyzer IP and Registration via Loopback details
        """        
        
        print("Checking FortiAnalyzer Settings")
        out=[]
        out.append("FortiAnalyzer IP")
        FAZ=self.fgt1.get(url="/api/v2/cmdb/log.fortianalyzer/setting/")
        faz_ip_cfgd=FAZ['server']
        faz_src_ip_cfgd=FAZ['source-ip']
        if faz_ip_cfgd==faz_ip:
            out.append(faz_ip_cfgd)
        else:
            out.append("Not Configured")
        out.append("Registered via Loopback")
        if(faz_src_ip_cfgd==self.Ipaddress):
            out.append("Yes")
        else:
            out.append("No")
        self.logger.debug(out)
        return out
    
    @log_function_call
    def get_bgp_neighbors_up(self: object)-> list[str]:
        """_summary_

        Args:
            self (object): fortigateAPI object

        Returns:
            list[str]: of IP address where BGP neighborship is established
        """        
        print("Checking BGP Up Details")
        BGP_N_Count=self.fgt1.get(url="/api/v2/monitor/router/bgp/neighbors")
        uplist=[]
        for entry in BGP_N_Count:
            if entry['state']=="Established":
                uplist.append(entry['neighbor_ip'])
        self.logger.debug(uplist)        
        return uplist
    
    @log_function_call
    def get_bgp_timers(self: object)-> list[str]:    
        """_summary_

        Args:
            self (object): fortigateAPI object

        Returns:
            list[str]: of timers BGP
        """
        print("Checking BGP Timers")
        timers=[]
        BGP_time=self.fgt1.get(url="/api/v2/cmdb/router/bgp")
        timers.append(str(BGP_time['keepalive-timer']))
        timers.append(str(BGP_time['holdtime-timer']))
        self.logger.debug(BGP_time)
        return timers
        
        
        
        
    @log_function_call
    def get_bgp_neighbors_down(self: object)-> list[str]:
        """_summary_

        Args:
            self (object): fortigateAPI object

        Returns:
            list[str]: of IP address where BGP neighborship is Idle
        """        
        print("Checking BGP Down Details")
        downlist=[]
        BGP_N_Count=self.fgt1.get(url="/api/v2/monitor/router/bgp/neighbors")
        for entry in BGP_N_Count:
            if entry['state']=="Idle":
                downlist.append(entry['neighbor_ip'])
        self.logger.debug(downlist) 
        return downlist
    
    @log_function_call
    def get_ipsec_data(self: object)-> list:
        """_summary_

        Args:
            self (object): fortigateAPI object

        Returns:
            list: of neighbors working state
        """
        print("Fetching IPSec Tunnels")
        TunnelList=[]
        data=self.fgt1.get(url="/api/v2/monitor/vpn/ipsec/")
        for entry in data:
            for proxy_entry in entry["proxyid"]:
                TunnelList.append(f"{proxy_entry['p2name']}-> {proxy_entry['status']}")
        self.logger.debug(TunnelList) 
        return TunnelList        
    
    @log_function_call
    def get_ipsec_up(self: object)-> list:
        """_summary_

            Args:
                self (object): fortigateAPI object

            Returns:
                list: of neighbors where status is Up
        """        
        print("Checking IPSec(Up) Tunnels")
        TunnelList=[]
        data=self.fgt1.get(url="/api/v2/monitor/vpn/ipsec/")
        for entry in data:
            for proxy_entry in entry["proxyid"]:
                if proxy_entry['status']=="up":
                    TunnelList.append(proxy_entry['p2name'])
        self.logger.debug(TunnelList) 
        return TunnelList
    
    @log_function_call
    def get_ipsec_down(self: object)-> list:
        """_summary_

        Args:
            self (object): fortigateAPI object

        Returns:
            list: of neighbors where status is Down
        """        
        print("Checking IPSec(Down) Tunnels")
        TunnelList=[]
        data=self.fgt1.get(url="/api/v2/monitor/vpn/ipsec/")
        for entry in data:
            for proxy_entry in entry["proxyid"]:
                if proxy_entry['status']=="down":
                    TunnelList.append(proxy_entry['p2name'])
        self.logger.debug(TunnelList) 
        return TunnelList
    
    @log_function_call
    def get_switch_data(self:object)->list:
        """_summary_
        Args:
            self (object): fortigateAPI object
        Returns:
            Dictionary: details such as Serial number,status, OS Version
        """  
        print("Checking Switch Details")
        result={}
        switchSN=self.fgt1.get(url="/api/v2/monitor/switch-controller/managed-switch/")
        result["Serial number"]=(switchSN[0]['serial'])
        result["Status"]=(switchSN[0]['status'])
        result["OS Version"]=(switchSN[0]['os_version'])
        self.logger.debug(result) 
        return result
             
    





