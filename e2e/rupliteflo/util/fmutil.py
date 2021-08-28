#
# $Header: lcmcmdtools/modules/rupliteflo/util/fmutil.py /st_lcmcmdtools_10.0.0.0.0/3 2021/07/08 19:54:43 huli Exp $
#
# fmutil.py
#
# Copyright (c) 2021, Oracle and/or its affiliates. 
#
#    NAME
#      fmutil.py - <one-line expansion of the name>
#
#    DESCRIPTION
#      script must be invoked by a python supporting http requests
#
#    NOTES
#      <other useful comments, qualifications, etc.>
#
#    MODIFIED   (MM/DD/YY)
#       mahnaray 05/05/21 - XbranchMerge mahnaray_bug-32532334 from
#                           st_lcmcmdtools_pt-e2e
#       after the change
#
import os
import requests
import argparse
import sys
import base64
import traceback
import time
import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))))
from ruplite.util import propfile
from ruplite import context
from flo.util import (parseutil, osutil)

OAUTHENDPOINT = "oauthEndpoint" 
E2EOAUTHCLIENTID = "E2EoauthClientId" 
E2EOAUTHCLIENTSECRET = "E2EOauthClientSecret"
E2EOAUTHTOKENSCOPE = "E2EOauthTokenScope"
E2EUSERNAME = "E2EUserName"
E2EPASSWORD = "E2EPassword"
STATUS_FAILURE=1
STATUS_SUCCESS=0
CREATED_STATUS=201

class FMService(object):

    def __init__(self, jsonfile, envfile):
        self.jsonfile = jsonfile  
        configprops = os.path.exists(envfile) and  propfile.loadprops(envfile) or {} 
        self.fm_rest_prop_file_loc = configprops.get("FM_REST_PROPERTY_FILE_LOC", "")
        self.connecttimeout =  int(configprops.get("FM_CONNECT_TIMEOUT",60))
        self.maxtimeout =  int(configprops.get("FM_MAX_TIMEOUT",120))
        self.retry_factor = int(configprops.get("FM_RETRY_FACTOR", 2))
        self.retry_sleep = int(configprops.get("FM_RETRY_SLEEP", 2))
        self.retry_times = int(configprops.get("FM_RETRY_TIMES", 5))
        self.user_entry = configprops.get("USER_ENTRY", "")
        self.pass_entry= configprops.get("PASS_PHRASE_ENTRY", "")
     
    def run_fm_post(self):
        if not os.path.exists(self.fm_rest_prop_file_loc):
            self._printlog("Error: FM posting property file %s doesn't exist" % self.fm_rest_prop_file_loc)
            return STATUS_FAILURE
        if not os.path.exists(self.jsonfile):
            self._printlog("Error: json file %s doesn't exist." % self.jsonfile)
            return STATUS_FAILURE 
        fm_post_props = propfile.loadprops(self.fm_rest_prop_file_loc) or {}
        fm_rest_url = fm_post_props.get("fmURL", "")
        if not fm_rest_url:
            self._printlog("Error FM posting URL is not specified")
            return STATUS_FAILURE
        auth_walletfile = fm_post_props.get("fmAuthWallet", "")
        auth_token_dict = None
        if auth_walletfile and os.path.exists(auth_walletfile):
            keys = [OAUTHENDPOINT, E2EOAUTHCLIENTID, E2EOAUTHCLIENTSECRET, E2EOAUTHTOKENSCOPE,\
                E2EUSERNAME, E2EPASSWORD]
            auth_token_dict = self._read_wallet_file(auth_walletfile, keys)
        else: 
            self._printlog("Check FM property file %s for fmAuthWallet property and the wallet file %s"\
              % (self.fm_rest_prop_file_loc, auth_walletfile))

        return self._post_to_fm(fm_rest_url, auth_token_dict, fm_post_props)

    def _post_to_fm(self, fm_rest_url, auth_token_prop, fm_post_props): 
        nretry = 0
        retry_sleep_time = self.retry_sleep * 60
        self._printlog("posting url:%s, jsonfile:%s" % (fm_rest_url, self.jsonfile))

        hd = {'Content-Type': 'application/vnd.oracle.adf.resourceitem+json'}
        user, passwd, auth_token = None, None, None
        while nretry < self.retry_times:
            try:
                if auth_token_prop:
                    auth_token = self._get_auth_token(auth_token_prop)
                if auth_token:
                    hd["Authorization"] = "Bearer %s" % auth_token
                    self._printlog("auth_token:%s" % base64.b64encode(auth_token))
                else:
                    hd.pop("Authorization", None)
                    if not user or not passwd:
                        walletfile=fm_post_props.get("fmWallet", "")
                        cred = self._read_wallet_file(walletfile, [self.user_entry,self.pass_entry])
                        if cred:
                            user = cred.get(self.user_entry, "")
                            passwd = cred.get(self.pass_entry, "")
                if auth_token or user and passwd: 
                    response = requests.post(fm_rest_url, data=open(self.jsonfile, 'rb'), headers=hd,\
                        auth=None if auth_token else (user, passwd),  timeout=(self.connecttimeout + (60 * nretry), self.maxtimeout + (60 * nretry)),\
                            verify=False)
                    self._printlog("response.status_code:%s , text:%s" % (response.status_code, response.text))
                    if response.status_code == CREATED_STATUS:
                        self._printlog("Post to FM succeeds")
                        return STATUS_SUCCESS
                else:
                    self._printlog("Can't retrieve credential, retrying...")
            except:
                self._printlog("Post to FM throws exception:%s, retrying" % traceback.format_exception(*sys.exc_info()))
            self._printlog("Retrying in %s seconds" % retry_sleep_time)
            time.sleep(retry_sleep_time)
            retry_sleep_time *= self.retry_factor
            nretry += 1
        self._printlog("Error: Post to fm failed after maximum number of retries")
        return STATUS_FAILURE

    def _get_auth_token(self, auth_token_prop):
        if auth_token_prop:
            from ssmutil import IDCSToken
            data = {'grant_type': 'password',
                    'username': auth_token_prop.get(E2EUSERNAME, ""),
                    'password': auth_token_prop.get(E2EPASSWORD, "")}
            tokencls = IDCSToken(client = "%s:%s" % (auth_token_prop.get(E2EOAUTHCLIENTID, ""),\
                       auth_token_prop.get(E2EOAUTHCLIENTSECRET, "")), idcsurl=auth_token_prop.get(OAUTHENDPOINT, ""),\
                       scope=auth_token_prop.get(E2EOAUTHTOKENSCOPE, ""), proxy="", \
                       connecttimeout = self.connecttimeout, maxtimeout = self.maxtimeout, exdata=data)
            nretry = 0
            retry_sleep_time = self.retry_sleep * 60
            while nretry < self.retry_times:
                try:
                    response = tokencls.gettoken()
                    self._printlog("get_auth_token response code: %s" % response.status_code)
                    token = parseutil.eval(response.text).get("access_token", "")
                    if token:
                        return token
                    else:
                        self._printlog("Token not found, response text: %s" % response.text)
                except:
                    self._printlog("_get_auth_token exception:%s" % traceback.format_exception(*sys.exc_info()))
                time.sleep(retry_sleep_time)
                retry_sleep_time *= self.retry_factor  
                nretry += 1
            self._printlog("Can't get the auth token after maximum number of retries") 
        return None

    def _printlog(self, msg):
        try:
            log_msg = "[%s] %s" % (datetime.datetime.now(), msg)
            print (log_msg.encode('utf-8'))
        except:
            pass

    def _read_wallet_file(self, walletfile, keys):
        if not os.path.exists(walletfile):
            self. _printlog("wallet file %s doesn't exist" % walletfile)
            return None
        cmd = "%s readautologinwallet %s %s" % (os.path.join(context.getrootdir(), "scripts",\
               "run_fusion_mc.sh"), walletfile, ' '.join(keys))
        exitcode, output = osutil._shell(cmd)
        if exitcode:
            self._printlog("Failed to execute: %s" % cmd)
            return None
        result_dict={}
        lines = output.split("\n")

        for key in keys:
            line = (filter(lambda x: x.startswith("result:%s=" % key), lines) + [None])[0]
            if not line:
                self._printlog("Wallet file problem. No result for %s from %s" % (key, cmd))
                return None
            value = line.split("=", 1)[1]
            result_dict[key] = value
        return result_dict

#process input args
ap = argparse.ArgumentParser()
ap.add_argument('-json', '--jsonfile', help='json file to be posted', required=True)
ap.add_argument('-envfile', '--envfile', help='FLO env file', required=True)
args = ap.parse_args()
<<<<<<< HEAD
fmservicemasterversion = FMService(args.jsonfile, args.envfile)
=======
fmservice = FMService(args.jsonfile, args.envfile)
>>>>>>> bug-12
sys.exit(fmservice111.run_fm_post())

#this is dev branch file
