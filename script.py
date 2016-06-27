#!/usr/bin/python
import subprocess
import os
#------------------NEUTRON_OAAS------------------------
#CHANGES
cambiado = False;
with open("/usr/lib/python2.7/dist-packages/neutron/common/topics.py") as f:
        for line in f:
                if "OPTIMIZER_PLUGIN = 'q-optimizer-plugin'" in line:
                        cambiado = True
if(cambiado == False):
        with open("/usr/lib/python2.7/dist-packages/neutron/common/topics.py") as f:
                with open("/usr/lib/python2.7/dist-packages/neutron/common/topics2.py", "w") as f1:
                        for line in f:
                                f1.write(line)
                                if "FIREWALL_PLUGIN = 'q-firewall-plugin'" in line:
                                        f1.write("OPTIMIZER_PLUGIN = 'q-optimizer-plugin'" + "\n")
cambiado = False;
with open("/usr/lib/python2.7/dist-packages/neutron/plugins/common/constants.py") as f:
        for line in f:
                if "'oaas': OPTIMIZER," in line:
                        cambiado = True
if(cambiado == False):
        with open("/usr/lib/python2.7/dist-packages/neutron/plugins/common/constants.py") as f:
                with open("/usr/lib/python2.7/dist-packages/neutron/plugins/common/constants2.py", "w") as f1:
                        for line in f:
                                f1.write(line)
                                if "FIREWALL = \"FIREWALL\"" in line:
                                        f1.write("OPTIMIZER = \"OPTIMIZER\"" + "\n")
                                if "'fwaas': FIREWALL," in line:
                                        f1.write("    'oaas': OPTIMIZER," + "\n")

if(os.path.exists("/usr/lib/python2.7/dist-packages/neutron/common/topics2.py")):
        subprocess.call("mv /usr/lib/python2.7/dist-packages/neutron/common/topics2.py /usr/lib/python2.7/dist-packages/neutron/common/topics.py", shell=True)
        subprocess.call("rm /usr/lib/python2.7/dist-packages/neutron/common/topics2.py", shell=True)
if(os.path.exists("/usr/lib/python2.7/dist-packages/neutron/plugins/common/constants2.py")):
        subprocess.call("mv /usr/lib/python2.7/dist-packages/neutron/plugins/common/constants2.py /usr/lib/python2.7/dist-packages/neutron/plugins/common/constants.py", shell=True)
        subprocess.call("rm /usr/lib/python2.7/dist-packages/neutron/plugins/common/constants2.py" , shell=True)

#Da igual mantener el error del firewall
subprocess.call("sed -i -e 's/nexception.OptimizerInternalDriverError/nexception.FirewallInternalDriverError/g' /usr/lib/python2.7/dist-packages/neutron_oaas/extensions/optimizer.py", shell=True)





#---------------------------NEUTRON----------------------------
#CHANGES
cambiado = False;
with open("/usr/lib/python2.7/dist-packages/neutron-7.0.0.egg-info/entry_points.txt") as f:
        for line in f:
                if "optimizer = neutron_oaas.services.optimizer.oaas_plugin:OptimizerPlugin" in line:
                        cambiado = True
if(cambiado == False):
        with open("/usr/lib/python2.7/dist-packages/neutron-7.0.0.egg-info/entry_points.txt") as f:
                with open("/usr/lib/python2.7/dist-packages/neutron-7.0.0.egg-info/entry_points2.txt", "w") as f1:
                        for line in f:
                                f1.write(line)
                                if "firewall = neutron_fwaas.services.firewall.fwaas_plugin:FirewallPlugin" in line:
                                        f1.write("optimizer = neutron_oaas.services.optimizer.oaas_plugin:OptimizerPlugin" + "\n")

if(os.path.exists("/usr/lib/python2.7/dist-packages/neutron-7.0.0.egg-info/entry_points2.txt")):
        subprocess.call("mv /usr/lib/python2.7/dist-packages/neutron-7.0.0.egg-info/entry_points2.txt /usr/lib/python2.7/dist-packages/neutron-7.0.0.egg-info/entry_points.txt", shell=True)
        subprocess.call("rm /usr/lib/python2.7/dist-packages/neutron-7.0.0.egg-info/entry_points2.txt", shell=True)


cambiado = False;
with open("/etc/neutron/policy.json") as f:
        for line in f:
                if "delete_optimizer_rule" in line:
                        cambiado = True
if(cambiado == False):
        with open("/etc/neutron/policy.json") as f:
                with open("/etc/neutron/policy2.json", "w") as f1:
                        for line in f:
                                f1.write(line)
                                if "\"delete_firewall_rule\": \"rule:admin_or_owner\"," in line:
                                        f1.write("    \"shared_optimizers\": \"field:optimizers:shared=True\"," + "\n" +
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
"    \"delete_optimizer_rule\": \"rule:admin_or_owner\"," + "\n")

if(os.path.exists("/etc/neutron/policy2.json")):
        subprocess.call("mv /etc/neutron/policy2.json /etc/neutron/policy.json", shell=True)
        subprocess.call("rm /etc/neutron/policy2.json", shell=True)

#--------------------------NEUTRONCLIENT------------------------
#CHANGES
cambiado = False;
with open("/usr/lib/python2.7/dist-packages/neutronclient/shell.py") as f:
        for line in f:
                if "from neutronclient.neutron.v2_0.opt import optimizer" in line:
			cambiado = True
if(cambiado == False):
	with open("/usr/lib/python2.7/dist-packages/neutronclient/shell.py") as f:
 		with open("/usr/lib/python2.7/dist-packages/neutronclient/shell2.py", "w") as f1:
       			for line in f:
               			f1.write(line) 
          			if "from neutronclient.neutron.v2_0.fw import firewallrule" in line:
                			f1.write("from neutronclient.neutron.v2_0.opt import optimizer" +"\n"+ 
					"from neutronclient.neutron.v2_0.opt import optimizerpolicy" + "\n" +
					"from neutronclient.neutron.v2_0.opt import optimizerrule" + "\n"
					) 
				if "'firewall-delete': firewall.DeleteFirewall," in line:
					f1.write("'optimizer-rule-list': optimizerrule.ListOptimizerRule,"+"\n" +
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
                                                   "'optimizer-delete': optimizer.DeleteOptimizer,"+"\n") 
cambiado = False
with open("/usr/lib/python2.7/dist-packages/neutronclient/v2_0/client.py") as f:
        for line in f:
                if "optimizer_rules_path = '/opt/optimizer_rules" in line:
                        cambiado = True
if(cambiado == False):
	with open("/usr/lib/python2.7/dist-packages/neutronclient/v2_0/client.py") as f:
        	with open("/usr/lib/python2.7/dist-packages/neutronclient/v2_0/client2.py", "w") as f1:
                	for line in f:
                        	f1.write(line)
                        	if "firewall_path =" in line:
                               		f1.write("    optimizer_rules_path = '/opt/optimizer_rules'"+ "\n" +
    "    optimizer_rule_path = '/opt/optimizer_rules/%s'"+ "\n" +
    "    optimizer_policies_path = '/opt/optimizer_policies'"+ "\n" +
    "    optimizer_policy_path = '/opt/optimizer_policies/%s'"+ "\n" +
    "    optimizer_policy_insert_path = '/opt/optimizer_policies/%s/insert_rule'"+ "\n" +
    "    optimizer_policy_remove_path = '/opt/optimizer_policies/%s/remove_rule'"+ "\n" +
    "    optimizers_path = '/opt/optimizers'"+ "\n" +
    "    optimizer_path = '/opt/optimizers/%s'"+ "\n" 
                                        )

				if "'firewalls': 'firewall'" in line:
					f1.write("                     'optimizer_rules': 'optimizer_rule',"+"\n"+
                     "                     	'optimizer_policies': 'optimizer_policy',"+"\n"+
                     "                     	'optimizers': 'optimizer',"+"\n"
						)
				if "return self.delete(self.firewall_path % (firewall))" in line:
					f1.write("    @APIParamsCall" + "\n"+
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
"        return self.delete(self.optimizer_path % (optimizer))" + "\n\n"
					)

if(os.path.exists("/usr/lib/python2.7/dist-packages/neutronclient/shell2.py")):
	subprocess.call("mv /usr/lib/python2.7/dist-packages/neutronclient/shell2.py /usr/lib/python2.7/dist-packages/neutronclient/shell.py", shell=True)
	subprocess.call("rm /usr/lib/python2.7/dist-packages/neutronclient/shell2.py", shell=True)
if(os.path.exists("/usr/lib/python2.7/dist-packages/neutronclient/v2_0/client2.py")):
	subprocess.call("mv /usr/lib/python2.7/dist-packages/neutronclient/v2_0/client2.py /usr/lib/python2.7/dist-packages/neutronclient/v2_0/client.py", shell=True)
	subprocess.call("rm /usr/lib/python2.7/dist-packages/neutronclient/v2_0/client2.py", shell=True)

#--------------------------------DATABASE-------------------------------
subprocess.call("mysql -u root --password='xxxx' -e 'use neutron;CREATE TABLE IF NOT EXISTS optimizers (tenant_id varchar(255) DEFAULT NULL,id varchar(36) NOT NULL,name varchar(255) DEFAULT NULL,description varchar(1024)  DEFAULT NULL,shared tinyint(1)  DEFAULT NULL,admin_state_up tinyint(1)  DEFAULT NULL,status varchar(16)  DEFAULT NULL,optimizer_policy_id varchar(36)  DEFAULT NULL,solowan tinyint(1)  DEFAULT NULL,local_id varchar(20)  DEFAULT NULL,action enum(\"optimization\",\"deduplication\",\"optimization deduplication\")  DEFAULT NULL,num_pkt_cache_size int(20) DEFAULT NULL,PRIMARY KEY(id),INDEX(tenant_id),INDEX(optimizer_policy_id));CREATE TABLE IF NOT EXISTS optimizer_policies (tenant_id varchar(255) DEFAULT NULL,id varchar(36) NOT NULL,name varchar(255) DEFAULT NULL,description varchar(1024)  DEFAULT NULL,shared tinyint(1)  DEFAULT NULL,audited tinyint(1) DEFAULT NULL,PRIMARY KEY(id),INDEX(tenant_id));CREATE TABLE IF NOT EXISTS optimizer_rules (tenant_id varchar(255) DEFAULT NULL,id varchar(36) NOT NULL,name varchar(255) DEFAULT NULL,description varchar(1024)  DEFAULT NULL,optimizer_policy_id varchar(36)  DEFAULT NULL,shared tinyint(1)  DEFAULT NULL,protocol varchar(40)  DEFAULT NULL,ip_version int(11)  NOT NULL,source_ip_address varchar(46)  DEFAULT NULL,destination_ip_address varchar(46)  DEFAULT NULL,source_port_range_min int(11)  DEFAULT NULL,source_port_range_max int(11)  DEFAULT NULL,destination_port_range_min int(11)  DEFAULT NULL,destination_port_range_max int(11)  DEFAULT NULL,action enum(\"allow\",\"deny\",\"reject\",\"optimize\")  DEFAULT NULL,enabled tinyint(1)  DEFAULT NULL,position int(11)  DEFAULT NULL,PRIMARY KEY(id),INDEX(tenant_id),INDEX(optimizer_policy_id));CREATE TABLE IF NOT EXISTS optimizer_router_associations (opt_id varchar(36) NOT NULL,router_id varchar(36) NOT NULL,PRIMARY KEY(opt_id,router_id)); ALTER TABLE optimizer_router_associations ADD FOREIGN KEY opt_id (opt_id) REFERENCES optimizers (id) ON DELETE CASCADE;ALTER TABLE optimizer_router_associations ADD FOREIGN KEY router_id (router_id) REFERENCES routers (id) ON DELETE CASCADE;'",shell=True)
cambiado = False;
with open("/usr/lib/python2.7/dist-packages/neutron/agent/l3/agent.py") as f:
        for line in f:
                if "from neutron.services.optimizer.agents.l3reference import optimizer_l3_agent" in line:
                        cambiado = True
if(cambiado == False):
    with open("/usr/lib/python2.7/dist-packages/neutron/agent/l3/agent.py") as f:
        with open("/usr/lib/python2.7/dist-packages/neutron/agent/l3/agent2.py", "w") as f1:
            for line in f:
                f1.write(line)
                if "from neutron.services.firewall.agents.l3reference import firewall_l3_agent" in line:
                    f1.write("try:" +"\n"+
"    from neutron_oaas.services.optimizer.agents.l3reference import optimizer_l3_agent" +"\n"+
"except Exception:" +"\n"+
"    # TODO(dougw) - REMOVE THIS FROM NEUTRON; during l3_agent refactor only" +"\n"+
"    from neutron.services.optimizer.agents.l3reference import optimizer_l3_agent" +"\n"
)
if(os.path.exists("/usr/lib/python2.7/dist-packages/neutron/agent/l3/agent2.py")):
        subprocess.call("mv /usr/lib/python2.7/dist-packages/neutron/agent/l3/agent2.py /usr/lib/python2.7/dist-packages/neutron/agent/l3/agent.py", shell=True)
        subprocess.call("rm /usr/lib/python2.7/dist-packages/neutron/agent/l3/agent2.py", shell=True)

cambiado = False;
with open("/usr/lib/python2.7/dist-packages/neutron/agent/l3/agent.py") as f:
        for line in f:
                if "class L3NATAgent(optimizer_l3_agent.OaaSL3AgentRpcCallback," in line:
                        cambiado = True
if(cambiado == False):
	subprocess.call("sed -i -e 's/class L3NATAgent(firewall_l3_agent.FWaaSL3AgentRpcCallback/class L3NATAgent(optimizer_l3_agent.OaaSL3AgentRpcCallback/g' /usr/lib/python2.7/dist-packages/neutron/agent/l3/agent.py", shell=True)



cambiado = False;
with open("/etc/neutron/plugins/ml2/ml2_conf.ini") as f:
        for line in f:
                if "optimizer_driver = neutron.agent.linux.iptables_optimizer.OVSHybridIptablesOptimizerDriver" in line:
                        cambiado = True
if(cambiado == False):
        with open("/etc/neutron/plugins/ml2/ml2_conf.ini") as f:
                with open("/etc/neutron/plugins/ml2/ml2_conf2.ini", "w") as f1:
                        for line in f:
                                f1.write(line)
                                if "firewall_driver = neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver" in line:
                                        f1.write("optimizer_driver = neutron.agent.linux.iptables_optimizer.OVSHybridIptablesOptimizerDriver")
if(os.path.exists("/etc/neutron/plugins/ml2/ml2_conf2.ini")):
        subprocess.call("mv /etc/neutron/plugins/ml2/ml2_conf2.ini /etc/neutron/plugins/ml2/ml2_conf.ini", shell=True)
        subprocess.call("rm /etc/neutron/plugins/ml2/ml2_conf2.ini", shell=True)

cambiado = False;
with open("/etc/neutron/l3_agent.ini") as f:
        for line in f:
                if "[oaas]" in line:
                        cambiado = True
if(cambiado == False):
	with open("/etc/neutron/l3_agent.ini", "a") as f1:
    		f1.write("[oaas]" + "\n" +
"driver = neutron.services.optimizer.drivers.linux.iptables_oaas.IptablesOaasDriver" + "\n" +
"enabled = True" + "\n")





#--------------------------------------DASHBOARD--------------------------------
#CHANGES
cambiado = False;
with open("/usr/share/openstack-dashboard/openstack_dashboard/conf/neutron_policy.json") as f:
        for line in f:
                if "\"delete_optimizer_rule\": \"rule:admin_or_owner\"" in line:
                        cambiado = True
if(cambiado == False):
        with open("/usr/share/openstack-dashboard/openstack_dashboard/conf/neutron_policy.json") as f:
                with open("/usr/share/openstack-dashboard/openstack_dashboard/conf/neutron_policy2.json", "w") as f1:
                        for line in f:
                                f1.write(line)
                                if "\"delete_firewall_rule\": \"rule:admin_or_owner\"," in line:
                                        f1.write("    \"shared_optimizers\": \"field:optimizers:shared=True\"," + "\n" +
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
"    \"delete_optimizer_rule\": \"rule:admin_or_owner\"," + "\n")
if(os.path.exists("/usr/share/openstack-dashboard/openstack_dashboard/conf/neutron_policy2.json")):
        subprocess.call("mv /usr/share/openstack-dashboard/openstack_dashboard/conf/neutron_policy2.json /usr/share/openstack-dashboard/openstack_dashboard/conf/neutron_policy.json", shell=True)
        subprocess.call("rm /usr/share/openstack-dashboard/openstack_dashboard/conf/neutron_policy2.json", shell=True)

cambiado = False;
with open("/usr/share/openstack-dashboard/openstack_dashboard/api/__init__.py") as f:
        for line in f:
                if "from openstack_dashboard.api import oaas" in line:
                        cambiado = True
if(cambiado == False):
        with open("/usr/share/openstack-dashboard/openstack_dashboard/api/__init__.py") as f:
                with open("/usr/share/openstack-dashboard/openstack_dashboard/api/__init2__.py", "w") as f1:
                        for line in f:
                                f1.write(line)
                                if "from openstack_dashboard.api import fwaas" in line:
                                        f1.write("from openstack_dashboard.api import oaas" + "\n")
				if "\"fwaas\"," in line:
                                        f1.write("    \"oaas\"," + "\n")
if(os.path.exists("/usr/share/openstack-dashboard/openstack_dashboard/api/__init2__.py")):
        subprocess.call("mv /usr/share/openstack-dashboard/openstack_dashboard/api/__init2__.py /usr/share/openstack-dashboard/openstack_dashboard/api/__init__.py", shell=True)
        subprocess.call("rm /usr/share/openstack-dashboard/openstack_dashboard/api/__init2__.py" , shell=True)


cambiado = False;
with open("/usr/share/openstack-dashboard/openstack_dashboard/templates/horizon/_scripts.html") as f:
        for line in f:
                if "<script src='{{ STATIC_URL }}horizon/js/horizon.optimizers.js'></script>" in line:
                        cambiado = True
if(cambiado == False):
        with open("/usr/share/openstack-dashboard/openstack_dashboard/templates/horizon/_scripts.html") as f:
                with open("/usr/share/openstack-dashboard/openstack_dashboard/templates/horizon/_scripts2.html", "w") as f1:
                        for line in f:
                                f1.write(line)
                                if "<script src='{{ STATIC_URL }}horizon/js/horizon.firewalls.js'></script>" in line:
                                        f1.write("<script src='{{ STATIC_URL }}horizon/js/horizon.optimizers.js'></script>" + "\n")
if(os.path.exists("/usr/share/openstack-dashboard/openstack_dashboard/templates/horizon/_scripts2.html")):
        subprocess.call("mv /usr/share/openstack-dashboard/openstack_dashboard/templates/horizon/_scripts2.html /usr/share/openstack-dashboard/openstack_dashboard/templates/horizon/_scripts.html", shell=True)
        subprocess.call("rm /usr/share/openstack-dashboard/openstack_dashboard/templates/horizon/_scripts2.html", shell=True)

#Compress statics
subprocess.call("/usr/share/openstack-dashboard/manage.py compress",shell=True)

cambiado = False;
with open("/usr/share/openstack-dashboard/openstack_dashboard/dashboards/project/stacks/mappings.py") as f:
        for line in f:
                if "'OPTIMIZER_COMPLETE': static_url + 'dashboard/img/optimizer-green.svg'" in line:
                        cambiado = True
if(cambiado == False):
        with open("/usr/share/openstack-dashboard/openstack_dashboard/dashboards/project/stacks/mappings.py") as f:
                with open("/usr/share/openstack-dashboard/openstack_dashboard/dashboards/project/stacks/mappings2.py", "w") as f1:
                        for line in f:
                                f1.write(line)
                                if "'link': 'horizon:project:firewalls:ruledetails'}" in line:
                                        f1.write("    \"OS::Neutron::Firewall\": {" + "\n" +
"        'link': 'horizon:project:optimizers:optimizerdetails'}," + "\n" +
"    \"OS::Neutron::FirewallPolicy\": {" + "\n" +
"        'link': 'horizon:project:optimizers:policydetails'}," + "\n" +
"    \"OS::Neutron::FirewallRule\": {" + "\n" +
"        'link': 'horizon:project:optimizers:ruledetails'}," + "\n")
                                if "'FIREWALL_COMPLETE': static_url + 'dashboard/img/firewall-green.svg'" in line:
                                        f1.write("    'OPTIMIZER_FAILED': static_url + 'dashboard/img/optimizer-red.svg'," + "\n" +
"    'OPTIMIZER_DELETE': static_url + 'dashboard/img/optimizer-red.svg'," + "\n" +
"    'OPTIMIZER_IN_PROGRESS': static_url + 'dashboard/img/optimizer-gray.gif'," + "\n" +
"    'OPTIMIZER_INIT': static_url + 'dashboard/img/optimizer-gray.svg'," + "\n" +
"    'OPTIMIZER_COMPLETE': static_url + 'dashboard/img/optimizer-green.svg'," + "\n")
if(os.path.exists("/usr/share/openstack-dashboard/openstack_dashboard/dashboards/project/stacks/mappings2.py")):
        subprocess.call("mv /usr/share/openstack-dashboard/openstack_dashboard/dashboards/project/stacks/mappings2.py /usr/share/openstack-dashboard/openstack_dashboard/dashboards/project/stacks/mappings.py", shell=True)
        subprocess.call("rm /usr/share/openstack-dashboard/openstack_dashboard/dashboards/project/stacks/mappings2.py ", shell=True)

