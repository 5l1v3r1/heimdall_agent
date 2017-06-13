import requests
import subprocess
import ConfigParser

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

    def getCVE(self,bid):
        data = {"id":bid}
        url = "http://vulners.com/api/v3/search/id/"
        r = requests.post(url,json=data)
        return r.json()["data"]["documents"][bid]["cvelist"]

    def getXPL(self,cveid):
        description,xpl_url= list(),list()
        url = "http://vulners.com/api/v3/search/lucene/"
        query = "cvelist:%s type:exploitdb" % cveid
        data = {"query":query}
        r = requests.post(url,json=data)
        response = r.json()["data"]["search"]
        if response:
            for xpl in response:
                description.append(xpl["_source"]["description"])
                xpl_url.append(xpl["_source"]["href"])
        return description,xpl_url

    def sendVulns(self,packages):
        self.getConf()
        data = {"key":self.conf['api'],"packages":dict()}
        for package in packages:
            data['packages'][package] = dict()
            for bid in packages[package]:
                cves = self.getCVE(bid)
                for cve in cves:
                    description,xpl = self.getXPL(cve)
                    data['packages'][package][cve] = description,xpl
        url = 'http://%s/api/v1/vulnerabilities' % self.conf['server']
        r = requests.post(url,json=data)
        return r.json()

    def VulnsUpdate(self,):
        self.getConf()
        packages = subprocess.Popen(self.getPackagesCmd[self.conf['distro']], stdout=subprocess.PIPE, shell=True).communicate()[0].split('\n')
        packages = [package for package in packages if package]
        environment = {'package':packages,'os':self.conf['distro'],'version':self.conf['distro_version']}
        response = self.getVulns(environment)
        packages = response['data']['packages']
        return self.sendVulns(packages)

    def getVulns(self,environment):
        url = 'https://vulners.com/api/v3/audit/audit/'
        r = requests.post(url,json=environment)
        return r.json()

if __name__ == '__main__':
    a = actions()
    a.VulnsUpdate()
