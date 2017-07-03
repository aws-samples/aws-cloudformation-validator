# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
  
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
  
#      http://www.apache.org/licenses/LICENSE-2.0
  
#  or in the "license" file accompanying this file. This file is distributed 
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either 
#  express or implied. See the License for the specific language governing 
#  permissions and limitations under the License.

#!/usr/bin/env python

from __future__ import print_function
import boto3
import botocore
import time
import sys
import argparse
import json
import urllib2
from pprint import pprint

aws_profile=""
aws_region=""

def get_template(template_file):

    '''
        Read a template file and return the contents
    '''
    try:
        if template_file.startswith("http"):
            response = urllib2.urlopen(template_file)
            cf_template = response.read()
        elif template_file.startswith("s3"):
            _, path = (template_file.split("//", 1))
            bucket_name, path = path.split("/", 1)

            global aws_profile

            if aws_profile:
                session = boto3.Session(profile_name=aws_profile)
                s3 = session.client('s3')
            else:
                s3 = boto3.client("s3")

            response = s3.get_object(Bucket=bucket_name, Key=path)
            cf_template = response['Body'].read()
        else:
            f = open(template_file, "r")
            cf_template = f.read()
    except:
        print("Error read file: ",template_file)

    return cf_template

def get_configuration(rules_file):

    '''
        Read a configuration from file or local
    '''

    cf_rules = get_template(rules_file)
    j_rules = json.loads(cf_rules)

    allow_root_keys = j_rules["allow_root_keys"]
    allow_parameters = j_rules["allow_parameters"]
    allow_resources = j_rules["allow_resources"]
    require_ref_attributes = j_rules["require_ref_attributes"]
    allow_additional_attributes = j_rules["allow_additional_attributes"]
    not_allow_attributes = j_rules["not_allow_attributes"]

    return allow_root_keys, allow_parameters, allow_resources, require_ref_attributes, allow_additional_attributes, not_allow_attributes

def validate_cf_template(cf_template, sc):

    '''
        Validate CF template
    '''
    global aws_region
    try:
        client = boto3.client('cloudformation', region_name=aws_region)
        response = client.validate_template(TemplateBody=cf_template)
        if ('Capabilities' in response) and (sc == "no"):
            print(response['Capabilities'],"=>>", response['CapabilitiesReason'])
            return False
        else:
            return True
    except:
        print(sys.exc_info()[1])
        return False

def validate_root_keys(cf_json_keys, valid_root_keys):

    '''
        Validate the root keys of CF template
    '''

    is_valid = False
    if not valid_root_keys:
        is_valid = True
    else:
        r = set(cf_json_keys) - set(valid_root_keys)
        if not r:
            is_valid = True

    return is_valid

def validate_parameters(cf_parameters, valid_parameters):

    '''
        Validate parameters of in CF template
    '''

    is_valid = False
    if not valid_parameters:
        is_valid = True
    else:
        r = set(cf_parameters) - set(valid_parameters)
        if not r:
            is_valid = True

    return is_valid

def validate_resources(cf_resources, valid_resources):

    '''
        Validate resources in CF template
    '''

    l_resource = []
    is_valid = False

    for rs in cf_resources.values():
        l_resource.append(rs["Type"].replace('AWS::',''))

    if (not valid_resources) or (not l_resource):
        is_valid = True
    else:
        r_set = set(l_resource) - set(valid_resources)
        if not r_set:
            is_valid = True
        else:
            for r in r_set:
                if ((r.split("::"))[0])+"::*" not in valid_resources:
                    return False
            is_valid = True

    return is_valid

def validate_attributes(cf_resources, require_ref_attributes, allow_additional_attributes, not_allow_attributes):

    '''
        Validate attributes of resources in CF template
    '''

    for rs in cf_resources.values():
        rs_type = rs["Type"].replace('AWS::','')
        ref_attr = []
        add_attr = []
        not_attr = []
        if rs_type in require_ref_attributes:
            ref_attr = require_ref_attributes[rs_type]
        if rs_type in allow_additional_attributes:
            add_attr = allow_additional_attributes[rs_type]
        if rs_type in not_allow_attributes:
            not_attr = not_allow_attributes[rs_type]

        if (ref_attr) or (add_attr) or (not_attr):
            for atr_key in rs["Properties"].keys():
                if atr_key in not_attr:
                    print('Not Allow Attribute: ', atr_key)
                    return False
                elif atr_key in ref_attr:
                    atr_val = rs["Properties"][atr_key]
                    if isinstance(atr_val, dict) and atr_val.keys()[0] not in 'Ref':
                        print('Not Refference Attribute: ',atr_key)
                        return False
                    elif isinstance(atr_val, list):
                        for o in atr_val:
                            if not isinstance(o, dict):
                                print('Not Refference - too nested: ', atr_key)
                                return False
                            elif o.keys()[0] not in 'Ref':
                                print('Not Refference - sub value:', atr_key)
                                return False
                    elif (not isinstance(atr_val, dict)) and (not isinstance(atr_val, list)):
                        print('Not Refference Attribute: ',atr_key)
                        return False
                elif add_attr and atr_key not in add_attr:
                    print('Not Allow attribute: ',atr_key)
                    return False

    return True

def validate_resources_exist(res_file):

    '''
        Validate if given AWS resource exists and are available
    '''
    global aws_profile
    global aws_region
    is_Valid = True
    cf_res = get_template(res_file)
    j_res = json.loads(cf_res)

    for r in j_res:
        if r["Type"] == "SG":
            try:
                if aws_profile:
                    session = boto3.Session(profile_name=aws_profile, region_name=aws_region)
                    ec2 = session.client('ec2')
                else:
                    ec2 = boto3.resource('ec2', region_name=aws_region)

                sg = ec2.SecurityGroup(r["ID"]).group_name
            except:
                print(sys.exc_info()[1])
                is_Valid = False

        elif r["Type"] == "AMI":
            try:
                if aws_profile:
                    session = boto3.Session(profile_name=aws_profile, region_name=aws_region)
                    ec2 = session.client('ec2')
                else:
                    ec2 = boto3.resource('ec2', region_name=aws_region)

                state = ec2.Image(r["ID"]).state
                if state != "available":
                    print("AMI Image not available")
                    is_Valid = False
            except:
                print(sys.exc_info()[1])
                is_Valid = False

        elif r["Type"] == "Subnet":
            try:
                if aws_profile:
                    session = boto3.Session(profile_name=aws_profile, region_name=aws_region)
                    ec2 = session.client('ec2')
                else:
                    ec2 = boto3.resource('ec2', region_name=aws_region)

                state = ec2.Subnet(r["ID"]).state
                if state != "available":
                    print("Subnet not available")
                    is_Valid = False
            except:
                print(sys.exc_info()[1])
                is_Valid = False

    return is_Valid

def main(arguments):
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--cf_path', required=True)
    parser.add_argument('--cf_rules', required=True)
    parser.add_argument('--cf_res',default='')
    parser.add_argument('--allow_cap',default='no')
    parser.add_argument('--region',default='us-east-1')
    parser.add_argument('--aws_profile',default='')
    args = parser.parse_args(arguments)

    global aws_profile
    aws_profile = args.aws_profile

    global aws_region
    aws_region = args.region

    cf_template = get_template(args.cf_path)
    try:
        j_cf = json.loads(cf_template)
    except:
        sys.exit("CF Template - not valid json format")

    if not validate_cf_template(cf_template, args.allow_cap):
        sys.exit("CF Template not valid")

    allow_root_keys, allow_parameters, allow_resources, require_ref_attributes, allow_additional_attributes, not_allow_attributes = get_configuration(args.cf_rules)

    if not validate_root_keys(j_cf.keys(),allow_root_keys):
        sys.exit("Root Tags are not valid")

    if not validate_parameters(j_cf["Parameters"].keys(),allow_parameters):
        sys.exit("Parameters are not valid")

    if not validate_resources(j_cf["Resources"],allow_resources):
        sys.exit("Resources are not valid")

    if not validate_attributes(j_cf["Resources"],require_ref_attributes, allow_additional_attributes, not_allow_attributes):
        sys.exit("Require Resources are not valid")

    if args.cf_res:
        if not validate_resources_exist(args.cf_res):
            sys.exit("Resources not found")

    print("CloudFormation Template Valid")

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
