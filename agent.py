import requests
import json
import pipes
import subprocess
import multiprocessing.pool
from flask import Flask,request
from plugin.heimdallagent import actions
from flask_apscheduler import APScheduler

app = Flask(__name__)


@app.route("/api/v1/update",methods=['POST'])
def hello():
    conf = actions().getConf()
    data = request.json
    if data['key'] == conf['api']:
        pool = multiprocessing.Pool(processes=None)
        pool.apply_async(updatePackage,(data['packages'],))
        return json.dumps({"status":"ok"})
    else:
        return json.dumps({"status":"not ok"})

def updatePackage(packages):
    for package in packages:
        package_name = package.split(' ')[0]
        conf = actions().getConf()
        cmd = "%s %s" % (conf['update_command'],pipes.quote(package_name))
        upgrade_status = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE, shell=True).communicate()
        verifyResponse(package,upgrade_status)

def verifyResponse(package_name,upgrade_status):
    if upgrade_status[1]:
        sendReponse(package_name,upgrade_status[1],'upgrade error')
    else:
        sendReponse(package_name,upgrade_status[0],'updated')

def sendReponse(package_name,upgrade_status,vulnerability_status):
    conf = actions().getConf()
    url = 'http://%s/api/v1/vulnerability/status' % conf['server']
    data = {'key':conf['api'],'upgrade_status':upgrade_status,'vulnerability_status':vulnerability_status,'package_name':package_name}
    r = requests.post(url,data=data)

def heartbeat():
    agent = actions()
    agent.heartBeat()

def vulnsupdate():
    agent = actions()
    agent.VulnsUpdate()


class Config(object):
    JOBS = [
        {
            'id': 'heartbeat',
            'func': heartbeat,
            'trigger': 'interval',
            'seconds': 120
        },
        {
            'id': 'vulnsupdate',
            'func': vulnsupdate,
            'trigger': 'interval',
            'seconds': 60
        }
        ]
    SCHEDULER_API_ENABLED = True

if __name__ == "__main__":
    print 'wait first vulnerability collect'
    heartbeat()
    vulnsupdate()
    print 'Done'
    app.config.from_object(Config())
    scheduler = APScheduler()
    scheduler.init_app(app)
    scheduler.start()
    app.run(host="0.0.0.0",port=5000)
