require 'git'
require 'sshkit'
require 'sshkit/dsl'
require 'rake/packagetask'

import 'hosts.rake'
# In hosts.rake, create a variable DEPLOYMENT_HOSTS which is an array of hosts to deploy to
# Create a variable SPLUNK_AUTH which is the username and password, e.g. admin:changeme

task :deploy do
  on DEPLOYMENT_HOSTS do |host|
    upload! 'target/snmpmod.spl', 'snmpmod.spl'
    execute "sudo /opt/splunk/bin/splunk install app snmpmod.spl -update 1 -auth #{SPLUNK_AUTH}"
    execute "sudo /opt/splunk/bin/splunk restart"
  end
end
