#!/usr/bin/env python

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

NULL_CAPABILITY = "/Capability=NULL"
NULL_ROLE = "/Role=NULL"

def filterOutNullCapability(fqan):
    return re.sub(NULL_CAPABILITY,"",fqan)

def filterOutNullRole(fqan):
    return re.sub(NULL_ROLE,"",fqan)


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

#DEFAULT_HOST = "fermicloud033.fnal.gov"
DEFAULT_HOST = "ferry.fnal.gov"
DEFAULT_PORT = 8443

class Ferry(object):
    def __init__(self, host=None, port=None):
        self.host = host if host else DEFAULT_HOST
        self.port = port if port is not None else DEFAULT_PORT
        self.url = "https://"+self.host+":"+str(self.port) + "/"

    def execute(self,query):
        url = self.url + query
        buffer = StringIO()
        c = pycurl.Curl()
        c.setopt(c.URL, url)

        """
        With very few exceptions, PycURL option names are derived from
        libcurl option names by removing the CURLOPT_ prefix.
        """

        c.setopt(c.CAPATH,"/etc/grid-security/certificates")
        c.setopt(c.SSLCERT,"/etc/grid-security/hostcert.pem")
        c.setopt(c.SSLKEY,"/etc/grid-security/hostkey.pem")

        c.setopt(c.WRITEFUNCTION, buffer.write)

        c.perform()
        rc=c.getinfo(pycurl.HTTP_CODE)
        c.close()

        if rc != 200 :
            raise Exception("Failed to execute query %s"%(rc,))
        return buffer.getvalue()

class FerryFileRetriever(object):

    def __init__(self, ferryconnect, query, filename=None):
        self.ferry = ferryconnect
        self.query = query
        self.filename = filename if filename else "/etc/grid-security"+query.lower()

    def write_file(self):
        data = self.ferry.execute(self.query)
        fd, name = tempfile.mkstemp(text=True)
        os.write(fd, data)
        os.close(fd)
        return name

    def retrieve(self):
        name = self.write_file()
        shutil.move(name, self.filename)

    def __repr__(self):
        return self.filename


class GridMapFile(FerryFileRetriever):

    def __init__(self,ferryconnect):
        super(GridMapFile,self).__init__(ferryconnect,
                                         "getGridMapFile",
                                         "/etc/grid-security/grid-mapfile")

    def write_file(self):
        data = self.ferry.execute(self.query)
        body =  json.load(StringIO(data))
        body.sort(key=lambda x: x["userdn"])
        fd, name = tempfile.mkstemp(text=True)
        map(lambda x: os.write(fd,"\"%s\" %s\n"%(x.get("userdn"),
                                                 x.get("mapped_uname"))),
            body)
        os.close(fd)
        return name


class StorageAuthzDb(FerryFileRetriever):

    def __init__(self, ferryconnect):
        super(StorageAuthzDb, self).__init__(ferryconnect,
                                             "getStorageAuthzDBFile",
                                             "/etc/grid-security/storage-authzdb")

    def write_file(self):
        data = self.ferry.execute(self.query)
        body =  json.load(StringIO(data))
        body.sort(key=lambda x: x["username"])
        fd, name = tempfile.mkstemp(text=True)
        for item in body:
            """
            user simons relies on dcache.kpwd
            """
            if item.get("username") == "simons" :
                continue
            if item.get("username") == "ifisk" :
                item["root"] = "/pnfs/fnal.gov/usr/Simons"
                item["uid"] = "49331"
                item["gid"] = ["9323",]
            if item.get("username") == "auger" :
                item["root"] = "/pnfs/fnal.gov/usr/fermigrid/volatile/auger"
            try:
                gids=map(int,item.get("gid"))
            except Exception as e:
                print item
                print str(e)
                continue
            gids.sort()
            os.write(fd,"%s\n"%(string.join([item.get("decision","authorize"),
                                             item.get("username"),
                                             item.get("privileges"),
                                             item.get("uid"),
                                             string.join(map(str,gids),","),
                                             item.get("home","/"),
                                             item.get("root"),
                                             item.get("last_path","/")],
                                            " ")))
        os.close(fd)
        return name

class VoGroup(FerryFileRetriever):



    def __init__(self, ferryconnect):
        super(VoGroup, self).__init__(ferryconnect,
                                         "getMappedGidFile",
                                         "/etc/grid-security/vo-group.json")

    def write_file(self):
        data = self.ferry.execute(self.query)
        body =  json.load(StringIO(data))
        body.sort(key=lambda x: x["fqan"])
        fd, name = tempfile.mkstemp(text=True)
        for item in body:
            item["fqan"] = filterOutNullRole(filterOutNullCapability(item.get("fqan")))
        os.write(fd,json.dumps(body, indent=4, sort_keys=True))
        return name

if __name__ == "__main__":

    try:
        f = Ferry()
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

    fail = False
    fails = {}
    for i in (GridMapFile(f), StorageAuthzDb(f), VoGroup(f)):
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







