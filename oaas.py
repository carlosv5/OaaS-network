#!/usr/bin/python
import os,sys,subprocess,time
from optparse import OptionParser

#-----------------------------------------------Script options
parser = OptionParser(usage='usage: %prog [options] ')
parser.add_option('-n', '--node',
                      type='choice',
                      action='store',
                      dest='node',
                      choices=['network', 'controller'],
                      help='Node to run on: network or controller')

parser.add_option('-s', '--service',
                      type='choice',
                      action='store',
                      dest='service',
                      choices=['optimizer', 'firewall'],
                      default='optimizer',
                      help='Service to run: optimizer or firewall. Default: optimizer')

#PATH
parser.add_option('-p', '--package',
                      action='store',
                      dest='packagesPath',
                      default='/usr/lib/python2.7/dist-packages',
                      help='Path of dist-packages. Default: /usr/lib/python2.7/dist-packages')

parser.add_option('-d', '--dashboard',
                      action='store',
                      dest='dashboardPath',
                      default='/usr/share/openstack-dashboard',
                      help='path of openstack-dashboard. Default: /usr/share/openstack-dashboard')

parser.add_option('-c', '--configuration',
                      action='store',
                      dest='confPath',
                      default='/etc/neutron',
                      help='path of neutron configuration folder. Default: /etc/neutron')

parser.add_option('-r', '--installPath',
                      action='store',
                      dest='installPath',
                      default='/tmp/OaaS-network',
                      help='Path of the git repository. Default: /tmp/OaaS-network ')

parser.add_option('-i', '--install',
                      action='store_true',
                      dest="installBoolean",
                      help='Install Optimizer as a Service. It is neccessary to have downloaded the entire repository. InstallPath gives its path')


(options, args) = parser.parse_args()


def main():
        print("----->Initializing neutron_oaas")
	neutron_oaas()
        print("----->Initializing neutron")
	neutron()
        print("----->Initializing neutronclient")
	neutronclient()
	if options.node == "controller":
        	print("----->Initializing database")
		database()
       		print("----->Initializing dashboard")
		dashboard()
		
        if options.node == "controller":
                print("----->Restarting neutron-server, wait please...")
                subprocess.call("service neutron-server restart",shell=True)
                print("----->Restarted neutron-server  succesfully")
                print("----->Restarting apache2, wait please...")
                subprocess.call("service apache2 restart",shell=True)
                print("----->Restarted apache2  succesfully")
        else:
                import time
                print("----->Restarting l3 agent. It takes 15 seconds, wait please...")
                time.sleep(15)
                subprocess.call("service neutron-l3-agent restart",shell=True)
                print("----->Restarted l3 agent succesfully")




def install():
	subprocess.call("chmod -R +xr " + options.installPath ,shell=True)
        print("----->Installing neutron")
	subprocess.call("cp -rp " + options.installPath + "/neutronclient/ " + options.packagesPath,shell=True)
        print("----->Installing neutronclient")
	subprocess.call("cp -rp  " + options.installPath + "/neutron_oaas/ " + options.packagesPath,shell=True)
        print("----->Installing neutron_oaas")
	subprocess.call("cp -rp  " + options.installPath + "/neutron_oaas-7.0.0.egg-info/ " + options.packagesPath,shell=True)
        print("----->Installing neutron_oaas info")
	subprocess.call("cp -rp  " + options.installPath + "/neutron/ " + options.packagesPath,shell=True)
        print("----->Installing neutron configuration")
	subprocess.call("cp -rp  " + options.installPath + "/etc/neutron/* " + options.confPath,shell=True)


	if options.node == "controller":
        	print("----->Installing oaas dashboard")
                subprocess.call("cp -p " + options.installPath  + "/horizon/static/horizon/js/horizon.optimizers.js " + options.packagesPath +"/horizon/static/horizon/js/horizon.optimizers.js",shell=True)
		subprocess.call("cp -rp " + options.installPath + "/openstack-dashboard/* "  + options.dashboardPath,shell=True)
       		print("----->Remember to add " + options.service + " to your service plugins [/etc/neutron/neutron.conf]")
	sys.exit(0)
#------------------------------------------Changes method
def changes(path, search, check, change):
    """This methods change de neccessary files"""

    #Check if the file has been changed
    cambiado = False
    arrayPath = os.path.splitext(path)
    with open(path) as f:
        for line in f:
            if check in line:
		cambiado = True
	#If it has not been changed, it changes it
    if(cambiado == False):
        with open(path) as f:
	    with open(arrayPath[0] +"2" + arrayPath[1], "w") as f1:
		for line in f:
		    f1.write(line)
		    if search in line:
		        f1.write(change  + "\n")
	#Mv the auxiliar file to the original
    if(os.path.exists(arrayPath[0] +"2" + arrayPath[1])):
        subprocess.call("mv " + arrayPath[0] +"2" + arrayPath[1] +" " + path, shell=True)



def neutron_oaas():
	#------------------NEUTRON_OAAS------------------------
	changes(options.packagesPath + "/neutron/common/topics.py","FIREWALL_PLUGIN = 'q-firewall-plugin'","OPTIMIZER_PLUGIN = 'q-optimizer-plugin'","OPTIMIZER_PLUGIN = 'q-optimizer-plugin'")

	changes(options.packagesPath + "/neutron/plugins/common/constants.py","FIREWALL = \"FIREWALL\"","OPTIMIZER = \"OPTIMIZER\"","OPTIMIZER = \"OPTIMIZER\"")
	changes(options.packagesPath + "/neutron/plugins/common/constants.py","'fwaas': FIREWALL","'oaas': OPTIMIZER","    'oaas': OPTIMIZER,")



def neutron():
	#---------------------------NEUTRON-7.0.0.egg-info----------------------------
	changes(options.packagesPath + "/neutron-7.0.0.egg-info/entry_points.txt","firewall = neutron_fwaas.services.firewall.fwaas_plugin:FirewallPlugin","optimizer = neutron_oaas.services.optimizer.oaas_plugin:OptimizerPlugin","optimizer = neutron_oaas.services.optimizer.oaas_plugin:OptimizerPlugin")

	#---------------------------NEUTRON----------------------------
	changes(options.confPath + "/policy.json","\"delete_firewall_rule\": \"rule:admin_or_owner\"","delete_optimizer_rule","    \"shared_optimizers\": \"field:optimizers:shared=True\"," + "\n" +
	"    \"shared_optimizer_policies\": \"field:optimizer_policies:shared=True\"," + "\n" +
	"    \"create_optimizer\": \"\"," + "\n" +
	"    \"get_optimizer\": \"rule:admin_or_owner\"," + "\n" +
	"    \"create_optimizer:shared\": \"rule:admin_only\"," + "\n" +
	"    \"get_optimizer:shared\": \"rule:admin_only\"," + "\n" +
	"    \"update_optimizer\": \"rule:admin_or_owner\"," + "\n" +
	"    \"update_optimizer:shared\": \"rule:admin_only\"," + "\n" +
	"    \"delete_optimizer\": \"rule:admin_or_owner\"," + "\n" +

	"    \"create_optimizer_policy\": \"\"," + "\n" +
	"    \"get_optimizer_policy\": \"rule:admin_or_owner or rule:shared_optimizer_policies\"," + "\n" +
	"    \"create_optimizer_policy:shared\": \"rule:admin_or_owner\"," + "\n" +
	"    \"update_optimizer_policy\": \"rule:admin_or_owner\"," + "\n" +
	"    \"delete_optimizer_policy\": \"rule:admin_or_owner\"," + "\n" +
	"    \"create_optimizer_rule\": \"\"," + "\n" +
	"    \"get_optimizer_rule\": \"rule:admin_or_owner or rule:shared_optimizers\"," + "\n" +
	"    \"update_optimizer_rule\": \"rule:admin_or_owner\"," + "\n" +
	"    \"delete_optimizer_rule\": \"rule:admin_or_owner\",")

	changes(options.packagesPath + "/neutron/agent/l3/agent.py","from neutron.services.firewall.agents.l3reference import firewall_l3_agent","from neutron.services.optimizer.agents.l3reference import optimizer_l3_agent","try:" +"\n"+
	"    from neutron_oaas.services.optimizer.agents.l3reference import optimizer_l3_agent" +"\n"+
	"except Exception:" +"\n"+
	"    # TODO(dougw) - REMOVE THIS FROM NEUTRON; during l3_agent refactor only" +"\n"+
	"    from neutron.services.optimizer.agents.l3reference import optimizer_l3_agent")

	changes(options.confPath + "/plugins/ml2/ml2_conf.ini","firewall_driver = neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver","optimizer_driver = neutron.agent.linux.iptables_optimizer.OVSHybridIptablesOptimizerDriver","optimizer_driver = neutron.agent.linux.iptables_optimizer.OVSHybridIptablesOptimizerDriver")

	changes(options.confPath + "/neutron.conf","service_provider=FIREWALL:Iptables:neutron.services.firewall.drivers.linux.iptables_fwaas.IptablesFwaasDriver","service_provider=OPTIMIZER:Iptables:neutron_oaas.services.optimizer.drivers.linux.iptables_oaas.IptablesOaasDriver","service_provider=OPTIMIZER:Iptables:neutron_oaas.services.optimizer.drivers.linux.iptables_oaas.IptablesOaasDriver")


	#Uniq changes -> Firewall or optimizer
	cambiado = False;
	if options.service == 'optimizer':
		with open(options.packagesPath + "/neutron/agent/l3/agent.py") as f:
			for line in f:
				if "class L3NATAgent(optimizer_l3_agent.OaaSL3AgentRpcCallback" in line:
				        cambiado = True
		if(cambiado == False):
			subprocess.call("sed -i 's/class L3NATAgent(firewall_l3_agent.FWaaSL3AgentRpcCallback/class L3NATAgent(optimizer_l3_agent.OaaSL3AgentRpcCallback/g' "+ options.packagesPath +"/neutron/agent/l3/agent.py", shell=True)
	else:
		with open(options.packagesPath + "/neutron/agent/l3/agent.py") as f:
			for line in f:
				if "class L3NATAgent(firewall_l3_agent.FWaaSL3AgentRpcCallback" in line:
				        cambiado = True
		if(cambiado == False):
			subprocess.call("sed -i  's/class L3NATAgent(optimizer_l3_agent.OaaSL3AgentRpcCallback/class L3NATAgent(firewall_l3_agent.FWaaSL3AgentRpcCallback/g' "+ options.packagesPath +"/neutron/agent/l3/agent.py", shell=True)
	#------------------
	cambiado = False;
	with open(options.confPath + "/l3_agent.ini") as f:
		for line in f:
		        if "[oaas]" in line:
		                cambiado = True
	if(cambiado == False):
		with open(options.confPath + "/l3_agent.ini", "a") as f1:
	    		f1.write("[oaas]" + "\n" +
	"driver = neutron_oaas.services.optimizer.drivers.linux.iptables_oaas.IptablesOaasDriver" + "\n" +
	"enabled = True" + "\n")
	#------------------

#--------------------------NEUTRONCLIENT------------------------
def neutronclient():
	changes(options.packagesPath + "/neutronclient/shell.py","from neutronclient.neutron.v2_0.fw import firewallrule","from neutronclient.neutron.v2_0.opt import optimizer","from neutronclient.neutron.v2_0.opt import optimizer" +"\n"+ 
						"from neutronclient.neutron.v2_0.opt import optimizerpolicy" + "\n" +
						"from neutronclient.neutron.v2_0.opt import optimizerrule")
	changes(options.packagesPath + "/neutronclient/shell.py","'firewall-delete': firewall.DeleteFirewall","'optimizer-delete': optimizer.DeleteOptimizer,","'optimizer-rule-list': optimizerrule.ListOptimizerRule,"+"\n" +
		                                           "'optimizer-rule-show': optimizerrule.ShowOptimizerRule,"+"\n" +
		                                           "'optimizer-rule-create': optimizerrule.CreateOptimizerRule,"+"\n" +
		                                           "'optimizer-rule-update': optimizerrule.UpdateOptimizerRule,"+"\n" +
		                                           "'optimizer-rule-delete': optimizerrule.DeleteOptimizerRule,"+"\n" +
		                                           "'optimizer-policy-list': optimizerpolicy.ListOptimizerPolicy,"+"\n" +
		                                           "'optimizer-policy-show': optimizerpolicy.ShowOptimizerPolicy,"+"\n" +
		                                           "'optimizer-policy-create': optimizerpolicy.CreateOptimizerPolicy,"+"\n" +
		                                           "'optimizer-policy-update': optimizerpolicy.UpdateOptimizerPolicy,"+"\n" +
		                                           "'optimizer-policy-delete': optimizerpolicy.DeleteOptimizerPolicy,"+"\n" +
		                                           "'optimizer-policy-insert-rule': optimizerpolicy.OptimizerPolicyInsertRule,"+"\n" +
		                                           "'optimizer-policy-remove-rule': optimizerpolicy.OptimizerPolicyRemoveRule,"+"\n" +
		                                           "'optimizer-list': optimizer.ListOptimizer,"+"\n" +
		                                           "'optimizer-show': optimizer.ShowOptimizer,"+"\n" +
		                                           "'optimizer-create': optimizer.CreateOptimizer,"+"\n" +
		                                           "'optimizer-update': optimizer.UpdateOptimizer,"+"\n" +
		                                           "'optimizer-delete': optimizer.DeleteOptimizer,")

	changes(options.packagesPath + "/neutronclient/v2_0/client.py","firewall_path =","optimizer_rules_path = '/opt/optimizer_rules","    optimizer_rules_path = '/opt/optimizer_rules'"+ "\n" +
	    "    optimizer_rule_path = '/opt/optimizer_rules/%s'"+ "\n" +
	    "    optimizer_policies_path = '/opt/optimizer_policies'"+ "\n" +
	    "    optimizer_policy_path = '/opt/optimizer_policies/%s'"+ "\n" +
	    "    optimizer_policy_insert_path = '/opt/optimizer_policies/%s/insert_rule'"+ "\n" +
	    "    optimizer_policy_remove_path = '/opt/optimizer_policies/%s/remove_rule'"+ "\n" +
	    "    optimizers_path = '/opt/optimizers'"+ "\n" +
	    "    optimizer_path = '/opt/optimizers/%s'")
	changes(options.packagesPath + "/neutronclient/v2_0/client.py","'firewalls': 'firewall'","'optimizers': 'optimizer',","                     'optimizer_rules': 'optimizer_rule',"+"\n"+
		             "                     	'optimizer_policies': 'optimizer_policy',"+"\n"+
		             "                     	'optimizers': 'optimizer',")
	changes(options.packagesPath + "/neutronclient/v2_0/client.py","return self.delete(self.firewall_path % (firewall))","'optimizer_policies': 'optimizer_policy',","                     'optimizer_rules': 'optimizer_rule',"+"\n"+
		             "                     	'optimizer_policies': 'optimizer_policy',"+"\n"+
		             "                     	'optimizers': 'optimizer',")
	changes(options.packagesPath + "/neutronclient/v2_0/client.py","return self.delete(self.firewall_path % (firewall))","def show_optimizer_rule(self, optimizer_rule, **_params):","    @APIParamsCall" + "\n"+
	"    def list_optimizer_rules(self, retrieve_all=True, **_params):" + "\n"+
	"        '''Fetches a list of all optimizer rules for a tenant.'''" + "\n"+
	"        # Pass filters in 'params' argument to do_request" + "\n"+
	"        return self.list('optimizer_rules', self.optimizer_rules_path," + "\n"+
	"                         retrieve_all, **_params)" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def show_optimizer_rule(self, optimizer_rule, **_params):" + "\n"+
	"        '''Fetches information of a certain optimizer rule.'''" + "\n"+
	"        return self.get(self.optimizer_rule_path % (optimizer_rule)," + "\n"+
	"                        params=_params)" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def create_optimizer_rule(self, body=None):" + "\n"+
	"        '''Creates a new optimizer rule.'''" + "\n"+
	"        return self.post(self.optimizer_rules_path, body=body)" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def update_optimizer_rule(self, optimizer_rule, body=None):" + "\n"+
	"        '''Updates a optimizer rule.'''" + "\n"+
	"        return self.put(self.optimizer_rule_path % (optimizer_rule), body=body)" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def delete_optimizer_rule(self, optimizer_rule):" + "\n"+
	"        '''Deletes the specified optimizer rule.'''" + "\n"+
	"        return self.delete(self.optimizer_rule_path % (optimizer_rule))" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def list_optimizer_policies(self, retrieve_all=True, **_params):" + "\n"+
	"        '''Fetches a list of all optimizer policies for a tenant.'''" + "\n"+
	"        # Pass filters in 'params' argument to do_request" + "\n"+
	"        return self.list('optimizer_policies', self.optimizer_policies_path," + "\n"+
	"                         retrieve_all, **_params)" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def show_optimizer_policy(self, optimizer_policy, **_params):" + "\n"+
	"        '''Fetches information of a certain optimizer policy.'''" + "\n"+
	"        return self.get(self.optimizer_policy_path % (optimizer_policy)," + "\n"+
	"                        params=_params)" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def create_optimizer_policy(self, body=None):" + "\n"+
	"        '''Creates a new optimizer policy.'''" + "\n"+
	"        return self.post(self.optimizer_policies_path, body=body)" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def update_optimizer_policy(self, optimizer_policy, body=None):" + "\n"+
	"        '''Updates a optimizer policy.'''" + "\n"+
	"        return self.put(self.optimizer_policy_path % (optimizer_policy)," + "\n"+
	"                        body=body)" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def delete_optimizer_policy(self, optimizer_policy):" + "\n"+
	"        '''Deletes the specified optimizer policy.'''" + "\n"+
	"        return self.delete(self.optimizer_policy_path % (optimizer_policy))" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def optimizer_policy_insert_rule(self, optimizer_policy, body=None):" + "\n"+
	"        '''Inserts specified rule into optimizer policy.'''" + "\n"+
	"        return self.put(self.optimizer_policy_insert_path % (optimizer_policy)," + "\n"+
	"                        body=body)" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def optimizer_policy_remove_rule(self, optimizer_policy, body=None):" + "\n"+
	"        '''Removes specified rule from optimizer policy.'''" + "\n"+
	"        return self.put(self.optimizer_policy_remove_path % (optimizer_policy)," + "\n"+
	"                        body=body)" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def list_optimizers(self, retrieve_all=True, **_params):" + "\n"+
	"        '''Fetches a list of all firewals for a tenant.'''" + "\n"+
	"        # Pass filters in 'params' argument to do_request" + "\n"+
	"        return self.list('optimizers', self.optimizers_path, retrieve_all," + "\n"+
	"                         **_params)" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def show_optimizer(self, optimizer, **_params):" + "\n"+
	"        '''Fetches information of a certain optimizer.'''" + "\n"+
	"        return self.get(self.optimizer_path % (optimizer), params=_params)" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def create_optimizer(self, body=None):" + "\n"+
	"        '''Creates a new optimizer.'''" + "\n"+
	"        return self.post(self.optimizers_path, body=body)" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def update_optimizer(self, optimizer, body=None):" + "\n"+
	"        '''Updates a optimizer.'''" + "\n"+
	"        return self.put(self.optimizer_path % (optimizer), body=body)" + "\n\n"+

	"    @APIParamsCall" + "\n"+
	"    def delete_optimizer(self, optimizer):" + "\n"+
	"        '''Deletes the specified optimizer.'''" + "\n"+
	"        return self.delete(self.optimizer_path % (optimizer))")

#--------------------------------DATABASE-------------------------------
def database():
	subprocess.call("mysql -u root --password='xxxx' -e 'use neutron;CREATE TABLE IF NOT EXISTS optimizers (tenant_id varchar(255) DEFAULT NULL,id varchar(36) NOT NULL,name varchar(255) DEFAULT NULL,description varchar(1024)  DEFAULT NULL,shared tinyint(1)  DEFAULT NULL,admin_state_up tinyint(1)  DEFAULT NULL,status varchar(16)  DEFAULT NULL,optimizer_policy_id varchar(36)  DEFAULT NULL,solowan tinyint(1)  DEFAULT NULL,local_id varchar(20)  DEFAULT NULL,action enum(\"optimization\",\"deduplication\",\"optimization deduplication\")  DEFAULT NULL,num_pkt_cache_size int(20) DEFAULT NULL,PRIMARY KEY(id),INDEX(tenant_id),INDEX(optimizer_policy_id));CREATE TABLE IF NOT EXISTS optimizer_policies (tenant_id varchar(255) DEFAULT NULL,id varchar(36) NOT NULL,name varchar(255) DEFAULT NULL,description varchar(1024)  DEFAULT NULL,shared tinyint(1)  DEFAULT NULL,audited tinyint(1) DEFAULT NULL,PRIMARY KEY(id),INDEX(tenant_id));CREATE TABLE IF NOT EXISTS optimizer_rules (tenant_id varchar(255) DEFAULT NULL,id varchar(36) NOT NULL,name varchar(255) DEFAULT NULL,description varchar(1024)  DEFAULT NULL,optimizer_policy_id varchar(36)  DEFAULT NULL,shared tinyint(1)  DEFAULT NULL,protocol varchar(40)  DEFAULT NULL,ip_version int(11)  NOT NULL,source_ip_address varchar(46)  DEFAULT NULL,destination_ip_address varchar(46)  DEFAULT NULL,source_port_range_min int(11)  DEFAULT NULL,source_port_range_max int(11)  DEFAULT NULL,destination_port_range_min int(11)  DEFAULT NULL,destination_port_range_max int(11)  DEFAULT NULL,action enum(\"allow\",\"deny\",\"reject\",\"optimize\")  DEFAULT NULL,enabled tinyint(1)  DEFAULT NULL,position int(11)  DEFAULT NULL,PRIMARY KEY(id),INDEX(tenant_id),INDEX(optimizer_policy_id));CREATE TABLE IF NOT EXISTS optimizer_router_associations (opt_id varchar(36) NOT NULL,router_id varchar(36) NOT NULL,PRIMARY KEY(opt_id,router_id)); ALTER TABLE optimizer_router_associations ADD FOREIGN KEY opt_id (opt_id) REFERENCES optimizers (id) ON DELETE CASCADE;ALTER TABLE optimizer_router_associations ADD FOREIGN KEY router_id (router_id) REFERENCES routers (id) ON DELETE CASCADE;'",shell=True)


#--------------------------------------DASHBOARD--------------------------------
def dashboard():
	changes(options.dashboardPath + "/openstack_dashboard/conf/neutron_policy.json","\"delete_firewall_rule\": \"rule:admin_or_owner\"","\"delete_optimizer_rule\": \"rule:admin_or_owner\"","    \"shared_optimizers\": \"field:optimizers:shared=True\"," + "\n" +
	"    \"create_optimizer\": \"\"," + "\n" +
	"    \"get_optimizer\": \"rule:admin_or_owner\"," + "\n" +
	"    \"create_optimizer:shared\": \"rule:admin_only\"," + "\n" +
	"    \"get_optimizer:shared\": \"rule:admin_only\"," + "\n" +
	"    \"update_optimizer\": \"rule:admin_or_owner\"," + "\n" +
	"    \"delete_optimizer\": \"rule:admin_or_owner\"," + "\n" +

	"    \"create_optimizer_policy\": \"\"," + "\n" +
	"    \"get_optimizer_policy\": \"rule:admin_or_owner or rule:shared_optimizers\"," + "\n" +
	"    \"create_optimizer_policy:shared\": \"rule:admin_or_owner\"," + "\n" +
	"    \"update_optimizer_policy\": \"rule:admin_or_owner\"," + "\n" +
	"    \"delete_optimizer_policy\": \"rule:admin_or_owner\"," + "\n" +

	"    \"create_optimizer_rule\": \"\"," + "\n" +
	"    \"get_optimizer_rule\": \"rule:admin_or_owner or rule:shared_optimizers\"," + "\n" +
	"    \"create_optimizer_rule:shared\": \"rule:admin_or_owner\"," + "\n" +
	"    \"get_optimizer_rule:shared\": \"rule:admin_or_owner\"," + "\n" +
	"    \"update_optimizer_rule\": \"rule:admin_or_owner\"," + "\n" +
	"    \"delete_optimizer_rule\": \"rule:admin_or_owner\",")
	changes(options.dashboardPath + "/openstack_dashboard/api/__init__.py","from openstack_dashboard.api import fwaas","from openstack_dashboard.api import oaas","from openstack_dashboard.api import oaas")
	changes(options.dashboardPath + "/openstack_dashboard/api/__init__.py","\"fwaas\",","\"oaas\",","    \"oaas\",")

	changes(options.dashboardPath + "/openstack_dashboard/templates/horizon/_scripts.html","<script src='{{ STATIC_URL }}horizon/js/horizon.firewalls.js'></script>","<script src='{{ STATIC_URL }}horizon/js/horizon.optimizers.js'></script>","<script src='{{ STATIC_URL }}horizon/js/horizon.optimizers.js'></script>")
	changes(options.dashboardPath + "/openstack_dashboard/dashboards/project/stacks/mappings.py","'link': 'horizon:project:firewalls:ruledetails'}","'link': 'horizon:project:optimizers:optimizerdetails'},", "\"OS::Neutron::Firewall\": {" + "\n" +
	"        'link': 'horizon:project:optimizers:optimizerdetails'}," + "\n" +
	"    \"OS::Neutron::FirewallPolicy\": {" + "\n" +
	"        'link': 'horizon:project:optimizers:policydetails'}," + "\n" +
	"    \"OS::Neutron::FirewallRule\": {" + "\n" +
	"        'link': 'horizon:project:optimizers:ruledetails'},")
	changes(options.dashboardPath + "/openstack_dashboard/dashboards/project/stacks/mappings.py","'FIREWALL_COMPLETE': static_url + 'dashboard/img/firewall-green.svg'","'OPTIMIZER_COMPLETE': static_url + 'dashboard/img/optimizer-green.svg'","    'OPTIMIZER_FAILED': static_url + 'dashboard/img/optimizer-red.svg'," + "\n" +
	"    'OPTIMIZER_DELETE': static_url + 'dashboard/img/optimizer-red.svg'," + "\n" +
	"    'OPTIMIZER_IN_PROGRESS': static_url + 'dashboard/img/optimizer-gray.gif'," + "\n" +
	"    'OPTIMIZER_INIT': static_url + 'dashboard/img/optimizer-gray.svg'," + "\n" +
	"    'OPTIMIZER_COMPLETE': static_url + 'dashboard/img/optimizer-green.svg',")


	#Compress statics
	subprocess.call(options.dashboardPath + "/manage.py compress",shell=True)


if not options.node:   # if node is not given
    parser.error('Node not given. Do it with -n or --node. Options: network, controller')
    sys.exit(1)
if(options.installBoolean):
	install()
main()

