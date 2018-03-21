import requests,warnings,getpass
from zeep import Client
from requests import Session
from zeep.transports import Transport
# dependencies on zeep, requests

warnings.filterwarnings("ignore")
# suppress cert errors for self-signed DS cert

DS_host = input('Please enter DSM FQDN or IP:')
username = input('Please enter username:')
password = getpass.getpass('Please enter password:')
# get connection details to DSM

def DS_auth():
    # authenticate to DSM
    try:
        auth_req = requests.post('https://'+DS_host+':4119/rest/authentication/login/primary',json={"dsCredentials": {"userName": username,"password": password}},verify=False,headers={'Content-Type':'application/json'})
        return auth_req.text
    except:
        print('Incorrect Parameters')

def get_rulesets():
    # REST call to get rulesets
    cookie = 'sID=' + DS_auth()
    try:
        ruleset = requests.get('https://'+DS_host+':4119/rest/rulesets',verify=False,headers={'Content-Type':'application/json','Cookie': cookie})
        return ruleset.text
    except:
        print('Invalid Request')

def get_hosts():
    # REST call to get hosts
    cookie = 'sID=' + DS_auth()
    try:
        hosts = requests.get('https://'+DS_host+':4119/rest/hosts',verify=False,headers={'Content-Type':'application/json','Cookie': cookie})
        return hosts.text
    except:
        print('Invalid Request')

def get_specific_host():
    # SOAP call to get details on a secific host
    session = Session()
    session.verify = False
    transport = Transport(session=session)
    client = Client('https://'+DS_host+':4119/webservice/Manager?WSDL',transport=transport)
    sid = client.service.authenticate(username,password)
    hft = {'hostID':5,'type':'SPECIFIC_HOST'}
    # create complex Transport object
    host = client.service.hostDetailRetrieve(hft,'HIGH',sid)
    host = host[0]
    return host['overallDpiStatus']

def clear_recommendations_host():
    session = Session()
    session.verify = False
    transport = Transport(session=session)
    client = Client('https://'+DS_host+':4119/webservice/Manager?WSDL',transport=transport)
    sid = client.service.authenticate(username,password)
    host = client.service.hostRecommendationsClear(5,sid)

def recommendations_scan_host():
    session = Session()
    session.verify = False
    transport = Transport(session=session)
    client = Client('https://'+DS_host+':4119/webservice/Manager?WSDL',transport=transport)
    sid = client.service.authenticate(username,password)
    host = client.service.hostRecommendationScan(7,sid)

def get_all_hosts():
    # SOAP call to get all HostID
    session = Session()
    session.verify = False
    transport = Transport(session=session)
    client = Client('https://'+DS_host+':4119/webservice/Manager?WSDL',transport=transport)
    sid = client.service.authenticate(username,password)
    hosts = client.service.hostRetrieveAll(sid)
    return hosts

def get_policy_details_host():
    # SOAP call to get policy details per host
    hosts = get_all_hosts()
    session = Session()
    session.verify = False
    transport = Transport(session=session)
    client = Client('https://'+DS_host+':4119/webservice/Manager?WSDL',transport=transport)
    sid = client.service.authenticate(username,password)
    for host in hosts:
        securityProfileID = host['securityProfileID']
        if securityProfileID == None:
            continue
        else:
            hosts = client.service.securityProfileRetrieve(securityProfileID,sid)
            print(hosts)


recommendations_scan_host()
