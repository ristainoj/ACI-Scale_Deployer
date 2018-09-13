__author__ = 'josephristaino'
import argparse, logging, sys, getpass, re
from acisession import Session

def env_setup(ip, usr, pwd, https, port):


    while ip is None:
        ip = raw_input("Enter IP of APIC      :")
        if len(ip) == 0:
            print "URL is required"
            ip = None

    while https is None:
        prot = raw_input("HTTPS? [y/n]          :")
        if prot == "n" or prot == "N":
            https = False
        elif prot == "y" or prot == "Y":
            https = True
        else :
            print "Please Enter Y or N"
            https = None

    default = False
    while port is None:
        port = raw_input("Enter Port [None]     :")
        if len(port) == 0:
            default = True
        if default == False:
            try:
                int(port)
            except ValueError:
                print "Please enter an integer for a Port Number"
                port = None

    if port and https:
        url = str("https://" + ip + ":" + port)
    elif port:
        url = str("http://" + ip + ":" + port)
    elif https:
        url = str("https://" + ip)
    else:
        url = str("http://" + ip)

# Load username from ARGS or Prompt
    if usr == "admin":
        print "Using Default Username: admin"
    while usr is None:
        usr = raw_input( "Enter username        : ")
        if len(usr)==0:
            print "Username is required"
            usr = None

# Load PW from ARGS or Prompt
    while pwd is None:
        pwd = getpass.getpass( "Enter admin password  : ")
        pwd2 = getpass.getpass("Re-enter password     : ")
        if len(pwd)==0:
            pwd = None
        elif pwd!=pwd2:
            print "Passwords do not match"
            pwd = None
        elif " " in pwd:
            print "No spaces allowed in password"
            pwd = None
    print "\n"

    session = Session(url, usr, pwd, verify_ssl=False)
    resp = session.login(timeout=60)
    if resp is None or not resp.ok:
            logger.error("failed to login with cert credentials")
            #return None
            sys.exit()

    return session

def check_if_exists(tenant, ap, objectClass, object):

    tenantReg = "uni\/tn-(?P<tenant>.*)"
    apReg = "uni\/tn-(?P<tenant>.*)\/ap-(?P<ap>.+)"
    epgReg = "uni\/tn-(?P<tenant>.*)\/ap-(?P<ap>.+)\/epg-(?P<epg>.+)"
    vrfReg = "uni\/tn-(?P<tenant>.+)\/ctx-(?P<vrf>.+)"
    bdReg = "uni\/tn-(?P<tenant>.+)\/BD-(?P<bd>.+)"

    url = "/api/node/class/%s.json" %objectClass
    resp = session.get(url)
    json = resp.json()

    count = json['totalCount']
    for i in range(0, int(count)):
        if objectClass in json["imdata"][i]:
            dn = json["imdata"][i][objectClass]["attributes"]["dn"]
            if objectClass == "fvTenant":
                r1 = re.search(tenantReg, dn)
                if r1.group("tenant") == object:
                    return True

            if objectClass == "fvAp":
                r1 = re.search(apReg, dn)
                if (r1.group("tenant") == tenant and r1.group("ap") == ap):
                    return True

            if objectClass == "fvAEPg":
                r1 = re.search(epgReg, dn)
                if (r1.group("tenant") == tenant and r1.group("ap") == ap and r1.group("epg") == object):
                    return True
            if objectClass == "fvCtx":
                r1 = re.search(vrfReg, dn)
                if (r1.group("tenant") == tenant and r1.group("vrf") == object):
                    return True
            if objectClass == "fvBD":
                r1 = re.search(bdReg, dn)
                if (r1.group("tenant") == tenant and r1.group("bd") == object):
                    return True
    return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store", help="debug level", dest="debug", default="ERROR")
    parser.add_argument("--ip", action="store", dest="ip",help="APIC URL", default=None)
    parser.add_argument("--username", action="store", dest="username",help="admin username", default="admin")
    parser.add_argument("--password", action="store", dest="password",help="admin password", default=None)
    parser.add_argument("--https", action="store_true", dest="https",help="Specifies whether to use HTTPS authentication", default=None)
    parser.add_argument("--port", action="store", dest="port",help="port number to use for APIC communicaton", default=None)
    parser.add_argument("--tenant", action="store", help="tenant", dest="tenant", default=None)
    parser.add_argument("--ap", action="store", help="ap", dest="ap", default=None)
    parser.add_argument("--epg", action="store", help="epg", dest="epg", default=None)
    parser.add_argument("--bd", action="store", help="bd", dest="bd", default=None)
    parser.add_argument("--vrf", action="store", help="vrf", dest="vrf", default=None)
    parser.add_argument("--phydom", action="store", help="phydom", dest="phydom", default=None)
    parser.add_argument("--vmmdom", action="store", help="vmmdom", dest="vmmdom", default=None)
    parser.add_argument("--stpath", action="store", help="stpath", dest="stpath", default=None)
    parser.add_argument("--startVal", action="store", help="startVal", dest="startVal", default=None)
    parser.add_argument("--iterations", action="store", help="iterations", dest="iterations", default=None)
    parser.add_argument("--delete", action="store_true", help="delete the config", dest="delete", default=None)
    args = parser.parse_args()

    tenant     = args.tenant
    appProfile = args.ap
    EPG        = args.epg
    BD         = args.bd
    VRF        = args.vrf
    phyDom     = args.phydom
    vmmDom     = args.vmmdom
    stPath     = args.stpath
    START      = int(args.startVal)
    ITERATIONS = int(args.iterations)

    # configure logging
    logger = logging.getLogger("")
    logger.setLevel(logging.WARN)
    logger_handler = logging.StreamHandler(sys.stdout)
    fmt ="%(asctime)s.%(msecs).03d %(levelname)8s %(filename)"
    fmt+="16s:(%(lineno)d): %(message)s"
    logger_handler.setFormatter(logging.Formatter(
        fmt=fmt,
        datefmt="%Z %Y-%m-%d %H:%M:%S")
    )
    logger.addHandler(logger_handler)
    # set debug level
    args.debug = args.debug.upper()
    if args.debug == "DEBUG": logger.setLevel(logging.DEBUG)
    if args.debug == "INFO": logger.setLevel(logging.INFO)
    if args.debug == "WARN": logger.setLevel(logging.WARN)
    if args.debug == "ERROR": logger.setLevel(logging.ERROR)


    #Create Session Object
    session = env_setup(args.ip, args.username, args.password, args.https, args.port)

    if not args.delete:
        tenant_created = check_if_exists(args.tenant, args.ap, "fvTenant", args.tenant)
        ap_created = check_if_exists(args.tenant, args.ap, "fvAp", args.ap)
        epg_created = check_if_exists(args.tenant, args.ap, "fvAEPg", args.epg)
        vrf_created = check_if_exists(args.tenant, args.ap, "fvCtx", args.vrf)
        bd_created = check_if_exists(args.tenant, args.ap, "fvBD", args.bd)

        if not tenant_created:
            tenantUrl = "/api/node/mo/uni/tn-%s.json" % tenant
            tenantData = {"fvTenant":{"attributes":{"name":"%s" % tenant ,"status":"created"}}}
            resp = session.push_to_apic(tenantUrl, tenantData)
            if resp is None or not resp.ok:
                print "failed to POST Tenant Config %s" %tenant
                #return None
                sys.exit()
            else: print "Successfully created Tenant %s" %tenant
        else:
            print "Tenant %s already exists, skipping creation..." %tenant

        if not ap_created:
            apUrl = "/api/node/mo/uni/tn-%s/ap-%s.json" % (tenant, appProfile)
            apData = {"fvAp":{"attributes":{"name":"%s" % appProfile ,"status":"created"}}}
            resp = session.push_to_apic(apUrl, apData)
            if resp is None or not resp.ok:
                print "failed to POST Application Profile Config %s" %appProfile
                #return None
                sys.exit()
            else: print "Successfully created Application Profile %s in Tenant %s" %(appProfile, tenant)
        else:
            print "Application Profile %s in Tenant %s already exists, Please Use a New One!" %(appProfile, tenant)
            sys.exit()

        if not vrf_created:
            vrfUrl = "/api/node/mo/uni/tn-%s/ctx-%s.json" % (tenant, VRF)
            vrfData = {"fvCtx":{"attributes":{"name":"%s" % VRF ,"status":"created"}}}
            resp = session.push_to_apic(vrfUrl, vrfData)
            if resp is None or not resp.ok:
                print "failed to POST VRF Config %s" %VRF
                sys.exit()
            else: print "Successfully created VRF %s in Tenant %s" %(VRF, tenant)
        else:
            print "VRF %s in Tenant %s already exists, Please Use a New One!" %(VRF, tenant)
            sys.exit()
    elif args.delete:
        apUrl = "/api/node/mo/uni/tn-%s/ap-%s.json" % (tenant, appProfile)
        apData = {"fvAp":{"attributes":{"name":"%s" % appProfile ,"status":"deleted"}}}
        resp = session.push_to_apic(apUrl, apData)
        if resp is None or not resp.ok:
            print "failed to DELETE Application Profile Config %s" %appProfile
            #return None
            sys.exit()
        else: print "Successfully Deleted Application Profile %s in Tenant %s" %(appProfile, tenant)

        vrfUrl = "/api/node/mo/uni/tn-%s/ctx-%s.json" % (tenant, VRF)
        vrfData = {"fvCtx":{"attributes":{"name":"%s" % VRF ,"status":"deleted"}}}
        resp = session.push_to_apic(vrfUrl, vrfData)
        if resp is None or not resp.ok:
            print "failed to Delete VRF Config %s" %VRF
            sys.exit()
        else: print "Successfully Deleted VRF %s in Tenant %s" %(VRF, tenant)



    for x in range(START, START+ITERATIONS, 1):
        if not args.delete:
            #Push BD to APIC
            if BD is not None:
                bdUrl = "/api/node/mo/uni/tn-%s/BD-VLAN%s.json" % (tenant, str(x))
                bdData = {"fvBD":{"attributes":{"dn":"uni/tn-%s/BD-VLAN%s" % (tenant, str(x)),"name":"VLAN%s" % str(x) ,\
                          "arpFlood":"yes", "unkMacUcastAct":"flood","unicastRoute":"false","rn":"BD-VLAN%s" % str(x),\
                          "status":"created"},"children":[{"fvRsCtx":{"attributes":{"tnFvCtxName":"%s" %VRF,\
                          "status":"created,modified"}}}]}}
                resp = session.push_to_apic(bdUrl, bdData)
                if resp is None or not resp.ok:
                    print "failed to POST BD %s in Tenant %s" %(BD, tenant)
                    sys.exit()
                else: print "Successfully created BD %s%s in Tenant %s" %(BD, x, tenant)

                #Push EPG to APIC
                if EPG is not None:
                    epgUrl = "/api/node/mo/uni/tn-%s/ap-%s/epg-VLAN%s.json" % (tenant, appProfile, str(x))
                    epgData = {"fvAEPg":{"attributes":{"dn":"uni/tn-%s/ap-%s/epg-VLAN%s" % (tenant, appProfile, str(x)),\
                               "name":"VLAN%s" % str(x),"rn":"epg-VLAN%s" % str(x),"status":"created"},\
                               "children":[{"fvRsBd":{"attributes":{"tnFvBDName":"VLAN%s" %str(x),\
                               "status":"created,modified"},"children":[]}}]}}
                    resp = session.push_to_apic(epgUrl, epgData)
                    if resp is None or not resp.ok:
                        print "failed to POST EPG %s%s in Tenant %s / Application Profile %s" %(EPG, x, tenant, appProfile)
                        sys.exit()
                    else: print "Successfully created EPG %s%s in Tenant: %s / Application Profile: %s" \
                                %(EPG, x, tenant, appProfile)

                    #Associate Domains to EPG
                    if phyDom is not None:
                        phydomData = {"fvRsDomAtt":{"attributes":{"tDn":"uni/phys-%s" % phyDom,"instrImedcy":"immediate",\
                                   "resImedcy":"immediate","status":"created"},"children":[]}}
                        resp = session.push_to_apic(epgUrl, phydomData)
                        if resp is None or not resp.ok:
                             print "failed to POST Domain %s to EPG %s%s" %(phyDom, EPG, x)
                             sys.exit()
                        else: print "Successfully mapped domain %s to EPG %s%s" %(phyDom, EPG, x)
                        if stPath is not None:
                            stPathData = {"fvRsPathAtt":{"attributes":{"encap":"vlan-%s" %str(x),"instrImedcy":"immediate",\
                                          "tDn":"%s" %stPath,"status":"created"},"children":[]}}
                            resp = session.push_to_apic(epgUrl, stPathData)
                            if resp is None or not resp.ok:
                                 print "failed to POST Static Path %s to EPG %s%s" %(stPath, EPG, x)
                                 sys.exit()
                            else: print "Successfully mapped Static Path %s to EPG %s%s" %(stPath, EPG, x)

                    if vmmDom is not None:
                        vmmDomData = {"fvRsDomAtt":{"attributes":{"resImedcy":"immediate",\
                                      "tDn":"uni/vmmp-VMware/dom-%s" %vmmDom,"instrImedcy":"immediate","status":"created"}}}
                        resp = session.push_to_apic(epgUrl, vmmDomData)
                        if resp is None or not resp.ok:
                             print "failed to POST VMM Domain %s to EPG %s%s" %(vmmDom, EPG, x)
                             sys.exit()
                        else: print "Successfully mapped VMM Domain %s to EPG %s%s" %(vmmDom, EPG, x)
        elif args.delete:
            if BD is not None:
                bdUrl = "/api/node/mo/uni/tn-%s/BD-VLAN%s.json" % (tenant, str(x))
                bdData = {"fvBD":{"attributes":{"dn":"uni/tn-%s/BD-VLAN%s" % (tenant, str(x)),"name":"VLAN%s" % str(x) ,\
                          "arpFlood":"yes", "unkMacUcastAct":"flood","unicastRoute":"false","rn":"BD-VLAN%s" % str(x),\
                          "status":"deleted"}}}
                resp = session.push_to_apic(bdUrl, bdData)
                if resp is None or not resp.ok:
                    print "failed to DELETE BD %s in Tenant %s" %(BD, tenant)
                    sys.exit()
                else: print "Successfully Deleted BD %s%s in Tenant %s" %(BD, x, tenant)
