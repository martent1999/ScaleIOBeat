# -*- coding: utf-8 -*-
##########################################################################
#
# Copyright (c) 2017, Plexxi Inc. and its licensors.
#
# All rights reserved.
#
# Use and duplication of this software is subject to a separate license
# agreement between the user and Plexxi or its licensor.
#
##########################################################################

from __future__ import unicode_literals
from __future__ import print_function

import sys, time
import json
from subprocess import Popen, PIPE
import argparse

# Command line options exist to override all of these
debug = 0
debugtime = 0
host = '172.24.99.7'
user = 'admin'
password = 'VMware1!'
push = 1
curl = '/usr/bin/curl'
esuser = 'plexxi'
espassword = 'plexxi'
eshost = '172.24.99.100'

import requests


class SDC(object):
    def __init__(self):
        self.approved = None
        self.guid = None
        self.id = None
        self.ip = None
        self.mdm_connection_state = None
        self.name = None
#        self.on_vmware = None
        self.system_id = None

    @classmethod
    def from_json(cls, json):
        sdc = cls()
 
        sdc.approved = json['sdcApproved']
        sdc.guid = json['sdcGuid']
        sdc.id = json['id']
        sdc.ip = json['sdcIp']
        sdc.mdm_connection_state = json['mdmConnectionState']
        sdc.name = json['name']
#        sdc.on_vmware = json['onVmWare']
        sdc.system_id = json['systemId']

        return sdc


class SDS(object):
    def __init__(self):
        self.drl_mode = None
        self.fault_set_id = None
        self.id = None
        self.ip_list = None
        self.mdm_connection_state = None
        self.membership_state = None
        self.name = None
        self.num_of_io_buffers = None
#        self.on_vmware = None
        self.port = None
        self.protection_domain_id = None
        self.read_cache_enabled = None
        self.read_cache_frozen = None
        self.read_cache_memory_allocation_state = None
        self.read_cache_size_in_kb = None
        self.state = None

    @classmethod
    def from_json(cls, json):
        # TODO (kale) handle IP_List
        sds = cls()

        sds.drl_mode = json['drlMode']
        sds.fault_set_id = json['faultSetId']
        sds.id = json['id']
        sds.ip_list = json['ipList']
        sds.mdm_connection_state = json['mdmConnectionState']
        sds.membership_state = json['membershipState']
        sds.name = json['name']
        sds.num_of_io_buffers = json['numOfIoBuffers']
#        sds.on_vmware = json['onVmWare']
        sds.port = json['port']
        sds.protection_domain_id = json['protectionDomainId']
        sds.read_cache_enabled = json['rmcacheEnabled']
        sds.read_cache_frozen = json['rmcacheFrozen']
        sds.read_cache_memory_allocation_state = \
            json['rmcacheMemoryAllocationState']
        sds.read_cache_size_in_kb = json['rmcacheSizeInKb']
        sds.state = json['sdsState']

        return sds


class System(object):
    def __init__(self):
        self.mdm_management_port = None
#        self.primary_mdm_actor_port = None
        self.system_version_name = None
        self.capacity_alert_high_threshold_percent = None
        self.capacity_alert_critical_threshold_percent = None
        self.remote_read_only_limit_state = None
#        self.secondary_mdm_actor_port = None
#        self.tiebreaker_mdm_actor_port = None
#        self.tiebreaker_mdm_ip_list = None
#        self.mdm_management_ip_list = None
        self.default_is_volume_obfuscated = None
        self.restricted_sdc_mode_enabled = None
        self.install_id = None
        self.swid = None
        self.days_installed = None
        self.max_capacity_in_gb = None
        self.capacity_time_left_in_days = None
        self.enterprise_features_enabled = None
        self.is_initial_license = None
#        self.primary_mdm_actor_ip_list = None
#        self.secondary_mdm_actor_ip_list = None
#        self.mdm_mode = None
        self.cluster_state = None
        self.name = None
        self.id = None

        # Stats
        self.active_moving_in_bck_rebuild_jobs = None
        self.active_moving_in_fwd_rebuild_jobs = None
        self.active_moving_out_bck_rebuild_jobs = None
        self.active_moving_out_fwd_rebuild_jobs = None
        self.pending_moving_in_bck_rebuild_jobs = None
        self.pending_moving_in_fwd_rebuild_jobs = None
        self.pending_moving_out_bck_rebuild_jobs = None
        self.pending_moving_out_fwd_rebuild_jobs = None

        self.active_moving_in_rebalance_jobs = None
        self.active_moving_rebalance_jobs = None
        self.pending_moving_in_rebalance_jobs = None
        self.pending_moving_rebalance_jobs = None

    @classmethod
    def from_json(cls, json, stats_json):
        system = cls()

        system.mdm_management_port = json['mdmManagementPort']
#        system.primary_mdm_actor_port = json['primaryMdmActorPort']
        system.system_version_name = json['systemVersionName']
        system.capacity_alert_high_threshold_percent = \
            json['capacityAlertHighThresholdPercent']
        system.capacity_alert_critical_threshold_percent = \
            json['capacityAlertCriticalThresholdPercent']
        system.remote_read_only_limit_state = json['remoteReadOnlyLimitState']
#        system.secondary_mdm_actor_port = json['secondaryMdmActorPort']
#        system.tiebreaker_mdm_actor_port = json['tiebreakerMdmActorPort']
#        system.tiebreaker_mdm_ip_list = json['tiebreakerMdmIpList']
#        system.mdm_management_ip_list = json['mdmManagementIpList']
        system.default_is_volume_obfuscated = json['defaultIsVolumeObfuscated']
        system.restricted_sdc_mode_enabled = json['restrictedSdcModeEnabled']
        system.install_id = json['installId']
        system.swid = json['swid']
        system.days_installed = json['daysInstalled']
        system.max_capacity_in_gb = json['maxCapacityInGb']
        system.capacity_time_left_in_days = json['capacityTimeLeftInDays']
        system.enterprise_features_enabled = json['enterpriseFeaturesEnabled']
        system.is_initial_license = json['isInitialLicense']
#        system.primary_mdm_actor_ip_list = json['primaryMdmActorIpList']
#        system.secondary_mdm_actor_ip_list = json['secondaryMdmActorIpList']
        system.mdm_mode = json['mdmCluster']['clusterMode']
        system.mdm_cluster_state = json['mdmCluster']['clusterState']
        system.name = json['name']
        system.id = json['id']

        # Stats
        system.active_moving_in_bck_rebuild_jobs = \
            stats_json['activeMovingInBckRebuildJobs']
        system.active_moving_in_fwd_rebuild_jobs = \
            stats_json['activeMovingInFwdRebuildJobs']
        system.active_moving_out_bck_rebuild_jobs = \
            stats_json['activeMovingOutBckRebuildJobs']
        system.active_moving_out_fwd_rebuild_jobs = \
            stats_json['activeMovingOutFwdRebuildJobs']
        system.pending_moving_in_bck_rebuild_jobs = \
            stats_json['pendingMovingInBckRebuildJobs']
        system.pending_moving_in_fwd_rebuild_jobs = \
            stats_json['pendingMovingInFwdRebuildJobs']
        system.pending_moving_out_bck_rebuild_jobs = \
            stats_json['pendingMovingOutBckRebuildJobs']
        system.pending_moving_out_fwd_rebuild_jobs = \
            stats_json['pendingMovingOutFwdRebuildJobs']

        system.active_moving_in_rebalance_jobs = \
            stats_json['activeMovingInRebalanceJobs']
        system.active_moving_rebalance_jobs = \
            stats_json['activeMovingRebalanceJobs']
        system.pending_moving_in_rebalance_jobs = \
            stats_json['pendingMovingInRebalanceJobs']
        system.pending_moving_rebalance_jobs = \
            stats_json['pendingMovingRebalanceJobs']

        return system

    def is_rebuilding(self):
        return any([self.active_moving_in_bck_rebuild_jobs,
                    self.active_moving_in_fwd_rebuild_jobs,
                    self.active_moving_out_bck_rebuild_jobs,
                    self.active_moving_out_fwd_rebuild_jobs,
                    self.pending_moving_in_bck_rebuild_jobs,
                    self.pending_moving_in_fwd_rebuild_jobs,
                    self.pending_moving_out_bck_rebuild_jobs,
                    self.pending_moving_out_fwd_rebuild_jobs])

    def is_rebalancing(self):
        return any([self.active_moving_in_rebalance_jobs,
                    self.active_moving_rebalance_jobs,
                    self.pending_moving_in_rebalance_jobs,
                    self.pending_moving_rebalance_jobs])


class API(object):
    def __init__(self, username, password, ip_address, verify_ssl, timeout=5):
        self._username = username
        self._password = password
        self._ip_address = ip_address
        self._verify_ssl = False
        self._timeout = timeout

        self._session = None

    def list_sdc(self):
        json_sdc_list = self._call_api('/types/Sdc/instances').json()
        return [SDC.from_json(sdc) for sdc in json_sdc_list]

    def list_sds(self):
        json_sds_list = self._call_api('/types/Sds/instances').json()
        return [SDS.from_json(sds) for sds in json_sds_list]

    def get_system(self):
        # There should only be one system per gateway
        json_system = self._call_api('/types/System/instances').json()[0]
        json_system_stats = self._get_json_system_stats(json_system['id'])

        return System.from_json(json_system, json_system_stats)

    def _get_json_system_stats(self, system_id):
        path = '/instances/System::{}/relationships/Statistics'\
            .format(system_id)
        return self._call_api(path).json()

    def test_connection(self):
        response = self._call_api('/instances/')
        return response.status_code == 200

    def _create_session(self):
        self._session = requests.Session()
        self._session.headers.update(
            {'Accept': 'application/json'})
        self._update_token()

    def _update_token(self):
        response = requests.get(url=self._get_api_url('/login'),
                                auth=(self._username, self._password),
                                verify=self._verify_ssl,
                                timeout=self._timeout)

        response.raise_for_status()

        self._session.auth = ('', response.json())

    def _call_api(self, path, method='get'):
        # Create session if it hasn't been configured
        if not self._session:
            self._create_session()

        response = self._make_request(path, method)

        # On unauthorized response, update token retry
        if response.status_code == 401:
            self._update_token()
            response = self._make_request(path, method)

        # Leave responsibility for error handling upstream
        response.raise_for_status()

        return response

    def _make_request(self, path, method):
        return self._session.request(method=method,
                                     url=self._get_api_url(path),
                                     verify=self._verify_ssl,
                                     timeout=self._timeout)

    def _get_api_url(self, path):
        return 'https://{}/api{}'.format(self._ip_address, path)


#
# pushToElasticSearch(object)
#
# Pushes a JSON object into Elastic Search
#
def pushToElasticSearch(jsonObject):
    """
    Takes a JSON object and inserts it into Elastic Search
    """

    if (push):
        if (debug):
            print("debug: pushing data to:", eshost, "using username", esuser, "and password", espassword)
            
        # Create index name that looks like this: plexxi-beat-YYYY.MM-dd
        index = 'scaleio-beat-' + time.strftime("%Y.%m-%d")
        esurl = 'http://' + args.eshost + ':9200/' + index + '/external?pretty'
        esuserpass = args.esuser + ':' + args.espassword
        p = Popen([
            args.curl,
            '-XPOST',
            '-u',
            esuserpass,
            '-d',
            jsonObject,
            esurl
        ],
                  stdin=PIPE,
                  stdout=PIPE,
                  stderr=PIPE)
        output,err = p.communicate()
        print(output,err)
        return (p.returncode)
    else:
        return (0)


                                    

# Main

if __name__ == '__main__':

    # Parse arguments. Use defaults as defined above

    parser = argparse.ArgumentParser(prog='PlexxiBeat.py')
    parser.add_argument('--host', help='hostname of Plexxi Control instance', default=host)
    parser.add_argument('--user', help='user name for Plexxi Control instance', default=user)
    parser.add_argument('--password', help='password for Plexxi Control user', default=password)
    parser.add_argument('--push', type=int, help='do not push data into ElasticSearch', default=push)
    parser.add_argument('--curl', help='localion of "curl", default ' + curl, default=curl)
    parser.add_argument('--esuser', help='ElasticSearch username', default=esuser)
    parser.add_argument('--espassword', help='ElasticSearch password', default=espassword)
    parser.add_argument('--eshost', help='ElasticSearch host name', default=eshost)
    parser.add_argument('--debug', type=int, help='enable debug printing', default=debug)
    parser.add_argument('--debugtime', type=int, help="enable timing output printing", default=debugtime)
    
    args = parser.parse_args()
    
    if (args.debug):
        print('debug: host =', args.host)
        print('debug: user =', args.user)
        print('debug: password =', args.password)
        print('debug: debug =', args.debug)
        print('debug: push =', args.push)
        print('debug: eshost = ', args.eshost)
        print('debug: esuser = ', args.esuser)
        print('debug: espassword = ', args.espassword)
        

    api = API(username=args.user, password=args.password, ip_address=args.host, verify_ssl=False)

    # Get Cluster Info

    system = api.get_system()

    mySystem = {}
    mySystem['id'] = system.id
    mySystem['name'] = system.name
    mySystem['system-version'] = system.system_version_name
    mySystem['max-capacity'] = system.max_capacity_in_gb
    mySystem['mdm-cluster-state'] = system.mdm_cluster_state
    mySystem['mdm-mode'] = system.mdm_mode
    mySystem['@timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    mySystem['type'] = "scaleio-system"
    
    # stick into Elastic here

    rc = pushToElasticSearch(json.dumps(mySystem))

    # Get SDSs in this cluster
    
    sds = api.list_sds()
    for i in sds:
        mySds = {}
        mySds['name'] = i.name
        mySds['ip-address'] = i.ip_list
        mySds['mdm-state'] = i.mdm_connection_state
        mySds['state'] = i.state
        mySds['membership-state'] = i.membership_state
        mySds['id'] = i.id
        mySds['fault-set-id'] = i.fault_set_id
        mySds['protection-domain'] = i.protection_domain_id
        mySds['@timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        mySds['type'] = "scaleio-sds"
        mySds['cluster'] = mySystem['name']
        
        # Stick into Elastic DB here
    
        rc = pushToElasticSearch(json.dumps(mySds))

    # Get SDCs registered in this cluster
    sdc = api.list_sdc()
    for i in sdc:
        mySdc = {}
        mySdc['name'] = i.name
        mySdc['id'] = i.id
        mySdc['ip'] = i.ip
        mySdc['mdm-connection-state'] = i.mdm_connection_state
        mySdc['approved'] = i.approved
        mySdc['system-id'] = i.system_id
        mySdc['@timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        mySdc['type'] = "scaleio-sdc"
        mySdc['cluster'] = mySystem['name']
        
        # Stick into Elastic here
    
        rc = pushToElasticSearch(json.dumps(mySdc))


