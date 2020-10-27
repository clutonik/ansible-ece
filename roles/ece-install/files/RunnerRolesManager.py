import fire
import sys
import os
import argparse
import subprocess
import requests
from requests.auth import HTTPBasicAuth
import logging
import json

class RunnerRolesManager(object):
    def __init__(self,runner, ece_host, ece_user, ece_password):
        '''
        Class to manage roles for a runner in ECE
        '''
        self._runner = runner
        self._ece_host = ece_host
        self._ece_user = ece_user
        self._ece_password = ece_password
        self._runner_basic_roles = [ "beats-runner", "services-forwarder"]
        self._get_endpoint = 'http://{}:12400/api/v1/platform/infrastructure/runners/{}'.format(self._ece_host,self._runner)
        self._put_endpoint = 'http://{}:12400/api/v1/platform/infrastructure/runners/{}/roles'.format(self._ece_host,self._runner)

    def get_runner_info(self):
        '''
        get_runner_info Gets you the Runner information from Platform
        :returns: runner information in JSON format
        '''
        try:
            response = requests.get(self._get_endpoint, auth=HTTPBasicAuth(
                self._ece_user,self._ece_password), verify=False)
            if response.status_code != 200 and response.status_code != 404:
                logging.error('error fetching runner information. {}'.format(response))
                exit(1)
        except Exception as e:
            logging.error("Error interacting with ECE: {}".format(e))
            exit(1)
        return response

    def get_existing_roles(self):
        '''
        get_existing_roles invokes Get Runner ECE API to fetch runner information
        :returns: existing runner roles as list of dict
        '''
        runner_info = self.get_runner_info()
        return runner_info.json()['roles']

    def has_role(self, role_name):
        '''
        Supply the role name and this method will tell you if the runner has it.
        :param role_name: Pass in the role_name you want you want to check  
        :returns: True if the runner has the supplied role else False
        '''
        existing_roles_list = self.get_existing_roles()
        search = [ True if role_name in role.values() else False for role in existing_roles_list ]
        if True in search:
            return True
        else:
            return False

    def reset_roles(self):
        '''
        Method to reset roles to basic roles(Remove director,proxy and allocator roles)
        :returns: Returns 200 if successful.  
        '''
        # Building list of dictionary objects
        new_roles_list = [ { "role_name" : role } for role in self._runner_basic_roles ] 
        # Request body format accepted by ECE
        request_body = { "roles": new_roles_list }
        logging.debug("Request Body: {}".format(json.dumps(request_body,indent=3)))
        _HEADERS = {"Content-Type": "application/json"}
        try:
            response = requests.put(self._put_endpoint, auth=HTTPBasicAuth(
                self._ece_user,self._ece_password), headers=_HEADERS, data=json.dumps(request_body), verify=False)
            if response.status_code != 200:
                logging.error('error updating roles. {}'.format(response.text))
                exit(1)
            else:
                response_json = response.json()
                logging.info("Updated Roles: {}".format(response_json))
                return 201
        except Exception as e:
            logging.error("Error interacting with ECE: {}".format(e))
            exit(1)

    def update_roles(self, role_name, force):
        '''
        Method to update roles of a runner
        :param role_name: Specify the role name you want this runner to have [ allocator, directory, proxy] 
        :param force: Specify this option if you want to update Roles forcefully ['yes','no']
        :returns: Returns 200 is no change is need, 201 if the role was added to runner and 1 if there was an error
        '''
        # Update Roles if needed
        is_role_present = self.has_role(role_name) 
        if is_role_present == False or force == 'yes':
            # Adding basic runner roles into the new roles
            raw_role_list = [ role_name, "coordinator" ] + self._runner_basic_roles if role_name == "director" else [role_name] + self._runner_basic_roles 
            # Building list of dictionary objects
            new_roles_list = [ { "role_name" : role } for role in raw_role_list] 
            # Request body format accepted by ECE
            request_body = { "roles": new_roles_list }
            logging.debug("Request Body: {}".format(json.dumps(request_body,indent=3)))
            _HEADERS = {"Content-Type": "application/json"}
            try:
                response = requests.put(self._put_endpoint, auth=HTTPBasicAuth(
                    self._ece_user,self._ece_password), headers=_HEADERS, data=json.dumps(request_body), verify=False)
                if response.status_code != 200:
                    logging.error('error updating roles. {}'.format(response.text))
                    exit(1)
                else:
                    response_json = response.json()
                    logging.info("Updated Roles: {}".format(response_json))
                    return 201
            except Exception as e:
                logging.error("Error interacting with ECE: {}".format(e))
                exit(1)
        else:
            logging.info("Passed in Role: {} is already present, no need to update roles.".format(role_name))
            return 200 

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    fire.Fire(RunnerRolesManager)