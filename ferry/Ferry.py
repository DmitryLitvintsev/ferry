#!/usr/bin/env python3

from __future__ import print_function

import json
import os
import re
import requests
import shutil
import sys
import tempfile
import time
import urllib3
import yaml


urllib3.disable_warnings()


SUCCESS="success"
NULL_CAPABILITY = "/Capability=NULL"
NULL_ROLE = "/Role=NULL"


def filterOutNullCapability(fqan):
    return re.sub(NULL_CAPABILITY,"",fqan)


def filterOutNullRole(fqan):
    return re.sub(NULL_ROLE,"",fqan)


def massageWildcard(fqan):
    return re.sub("\/\*$","*",fqan)


def massageProduction(fqan):
    return re.sub("Role=production\*$","Role=production",fqan)


def print_error(text):
    sys.stderr.write(time.strftime("%Y-%m-%d %H:%M:%S",
                                   time.localtime(time.time()))+
                     " : " +text+"\n")
    sys.stderr.flush()


def print_message(text):
    sys.stdout.write(time.strftime("%Y-%m-%d %H:%M:%S",
                                   time.localtime(time.time()))+
                     " : " +
                     text+"\n")
    sys.stdout.flush()

"""
The config file has to have :

ferry_endpoint: https://example.org:8445

"""

CONFIG_FILE="/etc/ferry/ferry.yaml"

with open(CONFIG_FILE, "r") as f:
    configuration = yaml.safe_load(f)

FERRY_ENDPOINT = configuration["ferry_endpoint"]
DEFAULT_PORT = 8445


class Ferry:

    def __init__(self, url=None):
        self.url = url if url else FERRY_ENDPOINT
        if not self.url.endswith("/"):
            self.url += "/"
        self.session = requests.Session()
        self.session.cert = ("/etc/grid-security/hostcert.pem",
                             "/etc/grid-security/hostkey.pem")

        #self.session.verify = "/etc/grid-security/certificates"

        self.session.headers = { "accept" : "application/json",
                                 "content-type" : "application/json"}
        self.ping()


    def ping(self):
        url = self.url + "ping"
        response = self.session.get(url)
        response.raise_for_status()
        rc = response.status_code

        if rc != 200 :
            raise Exception("Failed to ping Ferry %s %s"%(url, rc,))
        data = response.json()


    def execute(self, query):
        url = self.url + query
        response =  self.session.get(url)
        rc = response.status_code

        if rc != 200 :
            raise Exception("Failed to execute query %s %s" % (url, rc))

        data = response.json()
        ferry_status = data.get("ferry_status")
        ferry_error = data.get("ferry_error",[])
        if ferry_status != SUCCESS:
            raise Exception("Ferry Failed to execute query %s %s : "%(url,
                                                                      " ".join(ferry_error)))
        else:
            return  data.get("ferry_output")



class FerryFileRetriever(object):

    def __init__(self, ferryconnect, query, filename=None):
        self.ferry = ferryconnect
        self.query = query
        self.filename = filename if filename else "/etc/grid-security"+query.lower()

    def write_file(self):
        data = self.ferry.execute(self.query)
        fd, name = tempfile.mkstemp(text=True)
        os.write(fd, json.dumps(data, indent=4, sort_keys=True))
        os.close(fd)
        return name

    def retrieve(self):
        name = self.write_file()
        shutil.move(name, self.filename)
        os.chmod(self.filename,0o644)

    def __repr__(self):
        return self.filename



class GridMapFile(FerryFileRetriever):

    def __init__(self,ferryconnect):
        super(GridMapFile,self).__init__(ferryconnect,
                                         "getGridMapFile",
                                         "/etc/grid-security/grid-mapfile")

    def write_file(self):
        dn_kword = "dn"
        name_kword = "username"
        body = self.ferry.execute(self.query)
        body = sorted(body, key=lambda x: x[dn_kword])
        fd, name = tempfile.mkstemp(text=True)
        for x in body:
            os.write(fd,str.encode("\"%s\" %s\n"%(x.get(dn_kword)
                                                  .replace("/postalCode","/PostalCode")
                                                  .replace("/street","/STREET"),
                                                  x.get(name_kword))))
        os.close(fd)
        return name


class StorageAuthzDb(FerryFileRetriever):

    def __init__(self, ferryconnect):
        super(StorageAuthzDb, self).__init__(ferryconnect,
                                             "getStorageAuthzDBFile",
                                             "/etc/grid-security/storage-authzdb")

    def write_file(self):
        body = self.ferry.execute(self.query)
        group_kword = "groups"
        home_kword = "homedir"
        path_kword = "path"
        body = sorted(body, key=lambda x: x["username"])
        fd, name = tempfile.mkstemp(text=True)
        for item in body:
            """
            user simons relies on dcache.kpwd
            """
            if item.get("username") == "simons" :
                continue
            if item.get("username") == "bjwhite":
                item["uid"] = "0"
                item.get(group_kword).append(0)
            if item.get("username") in ("litvinse", "fuess"):
                item.get(group_kword).append(0)
            if item.get("username") in ("ifisk","rrana",):
                item["root"] = "/pnfs/fnal.gov/usr/Simons"
                item["uid"] = 49331
                item[group_kword] = [9323,]
            if item.get("username") == "auger" :
                item["root"] = "/pnfs/fnal.gov/usr/fermigrid/volatile/auger"
            try:
                gids = map(int, item.get(group_kword))
            except Exception as e:
                continue
            gids = sorted(gids)
            s = "%s" % " ".join([item.get("decision","authorize"),
                                 item.get("username"),
                                 item.get("privileges"),
                                 str(item.get("uid")),
                                 ",".join(map(str,gids)),
                                 item.get(home_kword,"/"),
                                 item.get("root"),
                                 item.get(path_kword,"/")])

            os.write(fd, str.encode("%s\n" % s))
        os.close(fd)
        return name


class VoGroup(FerryFileRetriever):

    def __init__(self, ferryconnect):
        super(VoGroup, self).__init__(ferryconnect,
                                         "getMappedGidFile",
                                         "/etc/grid-security/vo-group.json")

    def write_file(self):
        body = self.ferry.execute(self.query)
        body = sorted(body, key=lambda x: x["fqan"], reverse=True)
        fd, name = tempfile.mkstemp(text=True)
        for item in body:
            item["fqan"] = massageProduction(massageWildcard(filterOutNullRole(filterOutNullCapability(item.get("fqan")))))
            item["mapped_gid"] = str(item["mapped_gid"])
        os.write(fd, str.encode(json.dumps(body, indent=4, sort_keys=True)))
        return name


class CapabilitySetAnalysis(FerryFileRetriever):

    def __init__(self, ferryconnect):
        super(CapabilitySetAnalysis, self).__init__(ferryconnect,
                                         "getCapabilitySet",
                                         "/etc/dcache/multimap.conf")


    def write_file(self):
        passwd = self.ferry.execute("getStorageAuthzDBFile?passwdmode")
        group = self.ferry.execute("getAllGroups")
        group = [i for i in group if i.get("grouptype") == "UnixGroup"]
        groups = {}
        for i in group:
            groups[i["groupname"]] = i["gid"]
        passwd = passwd.get("fermilab").get("resources").get("all")
        users = {}
        for i in passwd:
            users[i["username"]] = i["uid"]

        body = self.ferry.execute(self.query)
        fd, name = tempfile.mkstemp(text=True)

        for item in body:
            roles = item.get("roles")
            if not roles: continue
            uname = item.get("setname")

            uid = users.get(uname)
            if not uid:
                continue

            for role_data in roles:
                role = role_data.get("role")
                if not role : continue
                group_name = role_data.get("mappedgroup")

                gid = groups.get(group_name)
                if not gid:
                    continue


                if not group_name: continue
                unit_name = role_data.get("unitname")
                if role == "Analysis" :
                    fqan = "/"+unit_name
                    os.write(fd, str.encode("oidcgrp:%s username:%s uid:%s gid:%s,true\n" %
                             (fqan, uname, uid, gid)))
        os.close(fd)
        return name



class CapabilitySetPrd(FerryFileRetriever):

    def __init__(self, ferryconnect):
        super(CapabilitySetPrd, self).__init__(ferryconnect,
                                               "getCapabilitySet",
                                               "/etc/dcache/multimap_prd.conf")


    def write_file(self):
        passwd = self.ferry.execute("getStorageAuthzDBFile?passwdmode")
        group = self.ferry.execute("getAllGroups")
        group = [i for i in group if i.get("grouptype") == "UnixGroup"]
        groups = {}
        for i in group:
            groups[i["groupname"]] = i["gid"]
        passwd = passwd.get("fermilab").get("resources").get("all")
        users = {}
        for i in passwd:
            users[i["username"]] = i["uid"]

        body = self.ferry.execute(self.query)
        fd, name = tempfile.mkstemp(text=True)

        for item in body:
            roles = item.get("roles")
            if not roles: continue
            uname = item.get("setname")

            uid = users.get(uname)
            if not uid:
                continue

            for role_data in roles:
                role = role_data.get("role")
                if not role : continue
                group_name = role_data.get("mappedgroup")

                gid = groups.get(group_name)
                if not gid:
                    continue


                if not group_name: continue
                unit_name = role_data.get("unitname")
                if role != "Analysis" :
                    fqan = "/" + unit_name + "/" + role.lower()
                    os.write(fd, str.encode("oidcgrp:%s username:%s uid:%s gid:%s,true\n" %
                             (fqan, uname, uid, gid)))
        os.close(fd)
        return name


class Passwd(FerryFileRetriever):
    def __init__(self, ferryconnect):
        query = "getStorageAuthzDBFile?passwdmode"

        super(Passwd, self).__init__(ferryconnect,
                                     query,
                                     "/etc/grid-security/passwd")

    def write_file(self):
        body = self.ferry.execute(self.query)
        passwd = []
        b = []
        fd, name = tempfile.mkstemp(text=True)
        for k,v in body.items():
            for key, value in v.get("resources").items():
                b += filter(lambda x : x.get("uid") not in passwd, value)
                passwd += [x.get("uid") for x in value]
        b = sorted(b, key=lambda x: x["username"])
        for x in b:
            os.write(fd, str.encode("%s:x:%s:%s:\"%s\":%s:%s\n"%(x.get("username"),
                                                                 x.get("uid"),
                                                                 x.get("gid"),
                                                                 x.get("gecos"),
                                                                 x.get("homedir"),
                                                                 x.get("shell"),)))
        os.close(fd)
        return name


class BanFile(FerryFileRetriever):
    def __init__(self, ferryconnect):
        query = "getAllUsersFQANs?suspend=true"
        super(BanFile, self).__init__(ferryconnect,
                                      query,
                                      "/etc/dcache/ban_ferry.conf")

    def write_file(self):
        body = self.ferry.execute(self.query)
        passwd = []
        b = []
        fd, name = tempfile.mkstemp(text=True)
        os.write(fd,("alias user=org.dcache.auth.UserNamePrincipal\n"
                     "alias dn=org.globus.gsi.gssapi.jaas.GlobusPrincipal\n"
                     "alias kerberos=javax.security.auth.kerberos.KerberosPrincipal\n"
                     "alias fqan=org.dcache.auth.FQANPrincipal\n"
                     "alias sub=org.dcache.auth.JwtSubPrincipal\n").encode())
        for k, v in body.items():
            os.write(fd, str.encode("ban user:%s\n" % (k, )))
        body = self.ferry.execute("getAllUsers")
        for user in body:
            if user.get("banned"):
                os.write(fd, str.encode("ban sub:%s\n" % (user.get("vopersonid"),)))
        os.close(fd)
        return name


class Group(FerryFileRetriever):
    def __init__(self, ferryconnect):
        query = "getAllGroupsMembers"
        super(Group, self).__init__(ferryconnect,
                                    query,
                                    "/etc/grid-security/group")

    def write_file(self):
        body = self.ferry.execute(self.query)
        kword = "groupname"
        body = filter(lambda x: x["grouptype"] == "UnixGroup", body)

        body = sorted(body,key=lambda x: x[kword])
        fd, name = tempfile.mkstemp(text=True)
        for i in body:
            group = str(i.get(kword))
            if not group: continue
            if group.find(" ") != -1 :
                continue
            gid = i.get('gid')
            users = i.get("members",[])
            if not users : users = []
            users = filter(lambda x : x["username"] != "", users)
            users = sorted(users, key=lambda x: x["username"])
            os.write(fd, str.encode("%s:x:%s:%s\n" % (group, gid, ",".join([ x['username'] for x in users]))))
        os.close(fd)
        return name


def main():

    try:
        f = Ferry()
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

    fail = False
    fails = {}
    for i in (Passwd(f), Group(f), GridMapFile(f),
              StorageAuthzDb(f), VoGroup(f),
              CapabilitySetAnalysis(f), CapabilitySetPrd(f),
              BanFile(f)):
        try:
            i.retrieve()
        except Exception as e:
            fail = True
            fails[str(i)]=str(e)
            raise e

    if fail:
        print_error("Failed to retrieve")
        for key, value in fails.items():
             print_error("%s : %s"%(key, value,))
        sys.exit(1)


if __name__ == "__main__":
    main()
