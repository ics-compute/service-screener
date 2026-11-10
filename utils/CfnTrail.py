import atexit
import os
import uuid
import sys

import boto3
import botocore
from botocore.config import Config as bConfig

from utils.Config import Config
from utils.Tools import _warn, _info

## Class name decided by Sarika
class CfnTrail():
    additionalDesc = None
    def __init__(self):
        self.stackName = None
        self.stackCreated = False
        self.ownerPid = os.getpid()
        self.cleanupRegistered = False
        self.cfnTemplate = "zNullResourcesCfn.yml"
        self.stackPrefix = "ssv2-"
        self.defaultRegion = "us-east-1"
        self.ymlBody='''
AWSTemplateFormatVersion: '2010-09-09'
Description: '[aws-gh-ss-v2] Service Screener V2{}'

Conditions:
  HasNot: !Equals [ 'true', 'false' ]
 
# dummy (null) resource, never created
Resources:
  NullResource:
    Type: 'Custom::NullResource'
    Condition: HasNot 
'''
        self.ymlBodyOutput='''
Outputs:
  ExportsStackName:
    Value: !Ref 'AWS::StackName'
    Export:
      Name: !Sub 'ExportsStackName-${AWS::StackName}'
'''

        # self.boto3init()
        
    def boto3init(self, additionalDesc = None):
        self.bConfig = bConfig(
            region_name = self.getRegion()
        )
        
        ssBoto = Config.get('ssBoto', None)
        self.cfClient = ssBoto.client('cloudformation', config=self.bConfig)

        self.additionalDesc = additionalDesc
        
    def createStack(self):
        try:
            yml = self.ymlBody.format(self.additionalDesc) + self.ymlBodyOutput
            self.cfClient.create_stack(
                StackName=self.getStackName(),
                TemplateBody=yml
            )
            self.stackCreated = True
            # The main process also cleans up explicitly after generating output.
            # This fallback covers errors and early exits without running in forked workers.
            if not self.cleanupRegistered:
                atexit.register(self.deleteStack)
                self.cleanupRegistered = True
            msg = "Empty CF stack created successfully, name:" + self.getStackName()
            _info(msg, alwaysPrint=True)

        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
            print("----")
            sys.exit("Please grant cloudformation:CreateStack permission to the user and retry")

    def deleteStack(self):
        # Forked scanner workers inherit atexit callbacks. Only the process that
        # created this stack is authorized to perform its cleanup.
        if not self.stackCreated or os.getpid() != self.ownerPid:
            return True

        stackName = self.getStackName()
        try:
            self.cfClient.delete_stack(StackName=stackName)
            self.cfClient.get_waiter('stack_delete_complete').wait(
                StackName=stackName,
                WaiterConfig={'Delay': 2, 'MaxAttempts': 60}
            )
            self.stackCreated = False
            _info("Empty CF stack deleted successfully, name:" + stackName, alwaysPrint=True)
            return True
        except botocore.exceptions.ClientError as e:
            ecode = e.response['Error']['Code']
            emsg = e.response['Error']['Message']
            print(ecode, emsg)
        except botocore.exceptions.WaiterError as e:
            print("CloudFormation stack deletion did not complete: " + str(e))

        print("Unable to delete CF stack. Clean up the stack manually and verify cloudformation:DeleteStack permission.")
        return False
    
    def getStackName(self):
        if self.stackName == None:
            self.stackName = self.stackPrefix + uuid.uuid4().hex[0:12]
        
        return self.stackName
    
    def getRegion(self):
        allRegions = Config.get('PARAMS_REGION_ALL')
        if allRegions == True:
            r = self.defaultRegion
        else:
            params = Config.get("_SS_PARAMS")
            regions = params['regions'].split(',')
            r = regions[0]
        
        return r