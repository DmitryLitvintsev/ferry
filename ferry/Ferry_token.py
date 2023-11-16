#!/usr/bin/env python

from __future__ import print_function

import io
import json
import pycurl
import os
import re
import shutil
import string
import subprocess
import sys
import tempfile
import time
import urllib

from StringIO import StringIO

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

def execute_command(cmd):
    p = subprocess.Popen(cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         shell=True)
    output, errors = p.communicate()
    rc=p.returncode
    if rc:
        print_error("Command \"%s\" failed: rc=%d, error=%s"%(cmd,
                                                              rc,
                                                              errors.replace('\n',' ')))
    return rc

DEFAULT_HOST = "ferry"
DEFAULT_PORT = 8445

class Ferry(object):
    def __init__(self, host=None, port=None):
        self.host = host if host else DEFAULT_HOST
        self.port = port if port is not None else DEFAULT_PORT
        self.url = "https://"+self.host+":"+str(self.port) + "/"
        self.curl = pycurl.Curl()
        """
        With very few exceptions, PycURL option names are derived from
        libcurl option names by removing the CURLOPT_ prefix.
        """

        self.curl.setopt(pycurl.CAPATH,"/etc/grid-security/certificates")
        self.curl.setopt(pycurl.SSLCERT,"/etc/grid-security/hostcert.pem")
        self.curl.setopt(pycurl.SSLKEY,"/etc/grid-security/hostkey.pem")
        self.api_version = 1
        self.ping()

    def ping(self):
        url = self.url + "ping"
        buffer = io.BytesIO()
        self.curl.setopt(pycurl.URL, url)
        self.curl.setopt(pycurl.WRITEFUNCTION, buffer.write)

        self.curl.perform()
        rc=self.curl.getinfo(pycurl.HTTP_CODE)

        if rc != 200 :
            raise Exception("Failed to ping Ferry %s %s"%(url, rc,))

        data = json.load(StringIO(buffer.getvalue()))

        if isinstance(data, dict):
            self.api_version = 2

    def execute(self, query):
        url = self.url + query
        buffer = io.BytesIO()
        self.curl.setopt(pycurl.URL, url)
        self.curl.setopt(pycurl.WRITEFUNCTION, buffer.write)

        self.curl.perform()
        rc=self.curl.getinfo(pycurl.HTTP_CODE)

        if rc != 200 :
            raise Exception("Failed to execute query %s"%(rc,))

        data = json.load(StringIO(buffer.getvalue()))
        if self.api_version == 2:
            ferry_status = data.get("ferry_status")
            ferry_error = data.get("ferry_error",[])
            if ferry_status != SUCCESS:
                raise Exception("Ferry Failed to execute query %s %s : "%(url,
                                                                          " ".join(ferry_error)))
            else:
                return  data.get("ferry_output")
        return data
        #return json.load(StringIO(buffer.getvalue()))
        #return buffer.getvalue()

class FerryFileRetriever(object):

    def __init__(self, ferryconnect, query, filename=None):
        self.ferry = ferryconnect
        self.query = query
        self.filename = filename if filename else "/etc/grid-security"+query.lower()

    def write_file(self):
        data = self.ferry.execute(self.query)
        fd, name = tempfile.mkstemp(text=True)
        os.write(fd,json.dumps(data, indent=4, sort_keys=True))
        os.close(fd)
        return name

    def retrieve(self):
        name = self.write_file()
        shutil.move(name, self.filename)
        os.chmod(self.filename,0644)

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
        if self.ferry.api_version == 1:
            dn_kword = "userdn"
            name_kword = "mapped_uname"
        body = self.ferry.execute(self.query)
        body.sort(key=lambda x: x[dn_kword])
        fd, name = tempfile.mkstemp(text=True)
        map(lambda x: os.write(fd,"\"%s\" %s\n"%(x.get(dn_kword)
                                                 .replace("/postalCode","/PostalCode")
                                                 .replace("/street","/STREET"),
                                                 x.get(name_kword))),
            body)
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
        if self.ferry.api_version == 1:
            group_kword = "gid"
            home_kword = "home"
            path_kword = "fs_path"
        body.sort(key=lambda x: x["username"])
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
                if  self.ferry.api_version == 1:
                    item["uid"] = "49331"
                    item[group_kword] = ["9323",]
                else:
                    item["uid"] = 49331
                    item[group_kword] = [9323,]
            if item.get("username") == "auger" :
                item["root"] = "/pnfs/fnal.gov/usr/fermigrid/volatile/auger"
            try:
                gids = map(int, item.get(group_kword))
            except Exception as e:
                continue
            gids.sort()

            os.write(fd,"%s\n"%(string.join([item.get("decision","authorize"),
                                             item.get("username"),
                                             item.get("privileges"),
                                             str(item.get("uid")),
                                             string.join(map(str,gids),","),
                                             item.get(home_kword,"/"),
                                             item.get("root"),
                                             item.get(path_kword,"/")],
                                            " ")))
        os.close(fd)
        return name


class VoGroup(FerryFileRetriever):

    def __init__(self, ferryconnect):
        super(VoGroup, self).__init__(ferryconnect,
                                         "getMappedGidFile",
                                         "/etc/grid-security/vo-group.json")

    def write_file(self):
        body = self.ferry.execute(self.query)
        body.sort(key=lambda x: x["fqan"], reverse=True)
        fd, name = tempfile.mkstemp(text=True)
        for item in body:
            item["fqan"] = massageProduction(massageWildcard(filterOutNullRole(filterOutNullCapability(item.get("fqan")))))
            if self.ferry.api_version == 2:
                item["mapped_gid"] = str(item["mapped_gid"])
        os.write(fd,json.dumps(body, indent=4, sort_keys=True))
        return name

class CapabilitySet(FerryFileRetriever):

    def __init__(self, ferryconnect):
        super(CapabilitySet, self).__init__(ferryconnect,
                                         "getCapabilitySet",
                                         "/tmp/foo.json")

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

        f1 = open("/tmp/multimap.conf", "w")
        f2 = open("/tmp/multimap_prd.conf", "w")
        f = None

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
                    f = f1
                else:
                    fqan = "/" + unit_name + "/" + role.lower()
                    f = f2
                f.write("oidcgrp:%s username:%s uid:%s gid:%s,true\n" %
                        (fqan, uname, uid, gid))

        map(lambda x: x.close(), (f1, f2))

        fd, name = tempfile.mkstemp(text=True)
        os.write(fd,json.dumps(body, indent=4, sort_keys=True))
        return name


class Passwd(FerryFileRetriever):
    def __init__(self, ferryconnect):
        if ferryconnect.api_version == 2:
            query = "getStorageAuthzDBFile?passwdmode"
        else:
            query = "getStorageAuthzDBFile?passwdmode=true"

        super(Passwd, self).__init__(ferryconnect,
                                     query,
                                     "/etc/grid-security/passwd")

    def write_file(self):
        body = self.ferry.execute(self.query)
        passwd = []
        b = []
        fd, name = tempfile.mkstemp(text=True)
        for k,v in body.iteritems():
            for key, value in v.get("resources").iteritems():
                b += filter(lambda x : x.get("uid") not in passwd, value)
                passwd += [x.get("uid") for x in value]
        b.sort(key=lambda x: x["username"])
        map(lambda x: os.write(fd,"%s:x:%s:%s:\"%s\":%s:%s\n"%(x.get("username"),
                                                               x.get("uid"),
                                                               x.get("gid"),
                                                               x.get("gecos"),
                                                               x.get("homedir"),
                                                               x.get("shell"),)),
            b)
        os.close(fd)
        return name


class Group(FerryFileRetriever):
    def __init__(self, ferryconnect):
        if ferryconnect.api_version == 2:
            query = "getAllGroupsMembers"
        else:
            query = "getAllGroupsMembers"
        super(Group, self).__init__(ferryconnect,
                                    query,
                                    "/etc/grid-security/group")

    def write_file(self):
        body = self.ferry.execute(self.query)
        kword = "groupname"
        if self.ferry.api_version == 1:
            kword = "name"
            body = filter(lambda x: x["type"] == "UnixGroup", body)
        if self.ferry.api_version == 2:
            body = filter(lambda x: x["grouptype"] == "UnixGroup", body)

        body.sort(key=lambda x: x[kword])
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
            users.sort(key=lambda x: x["username"])
            os.write(fd,"%s:x:%s:%s\n" % (group, gid, string.join([ x['username'] for x in users],",")))
        os.close(fd)
        return name

if __name__ == "__main__":

    try:
        f = Ferry()
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

    fail = False
    fails = {}
    for i in (CapabilitySet(f),):

        try:
            i.retrieve()
        except Exception as e:
            fail = True
            fails[str(i)]=str(e)

    if fail:
        print_error("Failed to retrieve")
        for key, value in fails.items():
             print_error("%s : %s"%(key, value,))
        sys.exit(1)
