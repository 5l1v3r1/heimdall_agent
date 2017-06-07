import requests
import subprocess
import ConfigParser
from pprint import pprint

class actions(object):

    def __init__(self,):
        self.getPackagesCmd = {'redhat':'rpm -qa','amazon linux':'rpm -qa',
        'ubuntu':"dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'",
        'debian':"dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'",'centos':'rpm -qa',
        'fedora':'rpm -qa','oraclelinux':'rpm -qa'}

    def getConf(self,):
        self.conf = dict()
        Config = ConfigParser.ConfigParser()
        Config.read('etc/agent.conf')
        section = Config.sections()[0]
        for key in Config.options(section):
            self.conf[key] = Config.get(section,key)
        return self.conf

    def heartBeat(self,):
        self.getConf()
        url = 'http://%s/api/v1/heartbeat' % self.conf['server']
        data = {'key':self.conf['api']}
        r = requests.post(url,data=data)
        return r.json()

    def sendVulns(self,packages):
        self.getConf()
        url = 'http://%s/api/v1/vulnerabilities' % self.conf['server']
        data = {'key': self.conf['api'],'packages':packages}
        r = requests.post(url,data=data)
        return r.json()

    def VulnsUpdate(self,):
        self.getConf()

        packages = subprocess.Popen(self.getPackagesCmd[self.conf['distro']], stdout=subprocess.PIPE, shell=True).communicate()[0].split('\n')
        packages = [package for package in packages if package]
        environment = {'package':packages,'os':self.conf['distro'],'version':self.conf['distro_version']}
        response = self.getVulns(environment)
        packages = response['data']['packages'].keys()
        return self.sendVulns(packages)

    def getVulns(self,environment):
        url = 'https://vulners.com/api/v3/audit/audit/'
        r = requests.post(url,json=environment)
        return r.json()

if __name__ == '__main__':
    a = actions()
    a.VulnsUpdate()
