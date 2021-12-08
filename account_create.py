import boto3
import requests
import time
import sys
import os
import json

class GraphQlException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class GraphQl:
    def __init__(self, endpoint: str, access_key: str, secret_access_key: str) -> None:
        if not endpoint or type(endpoint) is not str:
            raise ValueError("endpoint is missing or not string type")

        if not access_key or type(access_key) is not str:
            raise ValueError("access_key is missing or not string type")

        if not secret_access_key or type(secret_access_key) is not str:
            raise ValueError("secret_access_key is missing or not string type")

        self.__endpoint = endpoint
        self.__access_key = access_key
        self.__secret_access_key = secret_access_key

    def get_endpoint(self) -> str:
        return self.__endpoint

    def get_access_key(self) -> str:
        return self.__access_key

    def get_secret_access_key(self) -> str:
        return self.__secret_access_key

    def run_query(self, query: str, variables: dict) -> dict:
        if not query or type(query) is not str:
            raise ValueError("query is missing or not string type")

        if not variables or type(variables) is not dict:
            raise ValueError("variables is missing or not dict type")

        print(f"Query: {query}")
        print(f"Variables: {variables}")

        response = requests.post(
            self.get_endpoint(),
            auth=(self.get_access_key(), self.get_secret_access_key()),
            json={'query': query, 'variables': variables}
        )

        if response.status_code != 200 or response.json().get("errors"):
            print("GraphQL query failed, throwing exception")
            raise GraphQlException(f"Query failed: {response.text}")

        response = response.json()
        print(f"Query result: {response}")

        return response


def get_create_account_mutation():
    return '''
        mutation CreateAWSAccount($input: CreateResourceInput!) {
            createResource(input: $input) {
                turbot {
                    id
                }
            }
        }
'''

def get_create_account_variables(parent_folder_id, aws_account_id):
    if not parent_folder_id or type(parent_folder_id) is not str:
        raise ValueError("parent_folder_id is missing or not string type")

    if not aws_account_id or type(aws_account_id) is not str:
        raise ValueError("parent_folder_id is missing or not string type")

    return {
        "input": {
            # the Turbot folder ID under which the account is getting imported.
            "parent": parent_folder_id,
            "type": "tmod:@turbot/aws#/resource/types/account",
            "data": {
                # The AWS account ID that needs to be imported.
                "Id": aws_account_id
            },
            "metadata": {
                "aws": {
                    # The AWS account id that needs to be imported.
                    "accountId": aws_account_id,
                    "partition": "aws"
                }
            }
        }
    }


def get_account_configuration_mutation():
    return '''
        mutation SetIamRoleArnPolicy($setIamRoleArnPolicy: CreatePolicySettingInput!, $setIamRoleExternalIdPolicy: CreatePolicySettingInput!) {
            IamRoleArnPolicy: createPolicySetting(input: $setIamRoleArnPolicy) {
                turbot {
                    id
                }
            }   
            IamRoleExternalIdPolicy: createPolicySetting(input: $setIamRoleExternalIdPolicy) {
                turbot {
                    id
                }
            }
        }
'''


def get_account_configuration_variables(aws_resource_id, role_arn, external_id):
    if not aws_resource_id or type(aws_resource_id) is not str:
        raise ValueError("aws_resource_id is missing or not string type")

    if not role_arn or type(role_arn) is not str:
        raise ValueError("role_arn is missing or not string type")

    if not external_id or type(external_id) is not str:
        raise ValueError("role_arn is missing or not string type")

    return {
        "setIamRoleArnPolicy": {
            "type": "tmod:@turbot/aws#/policy/types/turbotIamRole",
            # the Turbot resource ID returned from STEP 1.
            "resource": aws_resource_id,
            # role policy aka, can be retrieved from the AWS console.
            "value": role_arn,
            "precedence": "REQUIRED"
        },
        "setIamRoleExternalIdPolicy": {
            "type": "tmod:@turbot/aws#/policy/types/turbotIamRoleExternalId",
            "resource": aws_resource_id,  # the Turbot resource ID returned from STEP 1.
            # the External ID from the role using AWS console. It can be found next to trust relationship.
            "value": external_id,
            "precedence": "REQUIRED"
        }
    }


def import_account(aws_account_id, role_arn, external_id, parentFolder, endpoint, turbotAccessKey, turbotSecretKey):
    graphql_endpoint = endpoint
    turbot_access_key = turbotAccessKey
    turbot_secret_access_key = turbotSecretKey

    graph_ql = GraphQl(graphql_endpoint, turbot_access_key, turbot_secret_access_key)

    create_account_mutation = get_create_account_mutation()
    create_account_variables = get_create_account_variables(parentFolder, aws_account_id)

    response = graph_ql.run_query(create_account_mutation, create_account_variables)

    # aws_resource_id = response.get("data").get("createResource").get("turbot").get("id")
    aws_resource_id = response["data"]["createResource"]["turbot"]["id"]
    account_configuration_mutation = get_account_configuration_mutation()
    account_configuration_variables = get_account_configuration_variables(aws_resource_id, role_arn, external_id)

    graph_ql.run_query(account_configuration_mutation, account_configuration_variables)

    print("Example complete")

def selfinvoke(event, status):
  print("in envoke")
  lambda_client = boto3.client('lambda')
  function_name = os.environ['AWS_LAMBDA_FUNCTION_NAME']
  event['RequestType'] = status
  print('invoking itself ' + function_name)
  response = lambda_client.invoke(
    FunctionName=function_name, 
    InvocationType='Event',
    Payload=json.dumps(event)
  )

def respond_cloudformation(event, status, data=None):
  print("in cf respond function")
  responseBody = {
    'Status': status,
    'Reason': 'See the details in CloudWatch Log Stream',
    'PhysicalResourceId': event['ServiceToken'],
    'StackId': event['StackId'],
    'RequestId': event['RequestId'],
    'LogicalResourceId': event['LogicalResourceId'],
    'Data': data
  }

  print('Response = ' + json.dumps(responseBody))
  print(event)
  r = requests.put(
    event['ResponseURL'], 
    data=json.dumps(responseBody)
  )
  print(r)

def delete_respond_cloudformation(event, status, message):
  print("in delete")
  print(message)
  responseBody = {
    'Status': status,
    'Reason': message,
    'PhysicalResourceId': event['ServiceToken'],
    'StackId': event['StackId'],
    'RequestId': event['RequestId'],
    'LogicalResourceId': event['LogicalResourceId']
  }
  print("pre put")
  r = requests.put(
    event['ResponseURL'], 
    data=json.dumps(responseBody)
  )
  print(r)
  lambda_client = boto3.client('lambda')
  function_name = os.environ['AWS_LAMBDA_FUNCTION_NAME']
  print('Deleting resources and rolling back the stack.')
  lambda_client.delete_function(
    FunctionName=function_name
  )
  sys.exit(-1)
     

def main(event,context):
  print("Main")
  print(event)

  ssmClient = boto3.client('ssm')

  try:
    print("Parse Lambda Params")
    parentId = os.environ['parentId']
    turbotAccountId = os.environ['accountId']
    targetOrgId = os.environ['orgOuId']

    print("Parse SSM Params")
    response = ssmClient.get_parameter(
      Name='/biogen/account/create/turbot/accessKey',
      WithDecryption=True
    )
    turbotAccessKey = response['Parameter']['Value']

    response = ssmClient.get_parameter(
      Name='/biogen/account/create/turbot/secretKey',
      WithDecryption=True
    )
    turbotSecretKey = response['Parameter']['Value']

    response = ssmClient.get_parameter(
      Name='/biogen/account/create/turbot/url',
      WithDecryption=False
    )
    turbotUrl = response['Parameter']['Value']
    if turbotUrl[-1] == '/':
      endpoint = "{}api/v5/graphql"
    else:
      endpoint = "{}/api/v5/graphql"

    response = ssmClient.get_parameter(
      Name='/biogen/account/create/turbot/account',
      WithDecryption=False
    )
    turbotMasterAccount = response['Parameter']['Value']

    response = ssmClient.get_parameter(
      Name='/biogen/account/create/turbot/environment',
      WithDecryption=False
    )
    environment = response['Parameter']['Value']

    response = ssmClient.get_parameter(
      Name='/biogen/account/create/org/root',
      WithDecryption=True
    )
    rootOrgId = response['Parameter']['Value']

    response = ssmClient.get_parameter(
      Name='/biogen/account/create/name/template',
      WithDecryption=False
    )
    accountName = response['Parameter']['Value'].format(acct=turbotAccountId)

    response = ssmClient.get_parameter(
      Name='/biogen/account/create/email/template',
      WithDecryption=False
    )
    accountEmail = response['Parameter']['Value'].format(acct=turbotAccountId)

    response = ssmClient.get_parameter(
      Name='/biogen/account/create/org/assume/role',
      WithDecryption=True
    )
    orgAssumeRole = response['Parameter']['Value']

    response = ssmClient.get_parameter(
      Name='/biogen/account/create/org/assume/role/external/id',
      WithDecryption=True
    )
    orgExternalId = response['Parameter']['Value']
    
    response = ssmClient.get_parameter(
      Name='/biogen/account/create/turbot/role',
      WithDecryption=True
    )
    accountRole = response['Parameter']['Value']

    response = ssmClient.get_parameter(
      Name='/biogen/account/create/turbot/role/external/id',
      WithDecryption=True
    )
    turbotExternalId = response['Parameter']['Value']
  
    #leave hardcoded
    orgSessionName = "TurbotAccountBootstrap"
    accessToBilling = "ALLOW"
    awsAccountId = None

  except Exception as e:
    print("ERROR: {}".format(e))
    delete_respond_cloudformation(
      event, 
      "FAILED", 
      "Parameter Error: {}".format(e))

  print("params parsing finished.")
  
  if (event['RequestType'] == 'Create'):
    print("Template Create Requested")
    selfinvoke(event, 'Wait')
    print("clients")
    try:
      local_client = boto3.client('sts')
      sts_response = local_client.assume_role(
        RoleArn=orgAssumeRole,
        RoleSessionName=orgSessionName,
        ExternalId=orgExternalId
      )

      org_client = boto3.client(
        'organizations', 
        aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
        aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'], 
        aws_session_token=sts_response['Credentials']['SessionToken'],
        region_name='us-east-1'
      )

      org_sts_client = boto3.client(
        'sts', 
        aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
        aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'], 
        aws_session_token=sts_response['Credentials']['SessionToken'],
        region_name='us-east-1'
      )

    except Exception as e:
      print("ERROR: {}".format(e))
      delete_respond_cloudformation(
        event, 
        "FAILED", 
        "Connection Error: {}".format(e))

    print("Create Start")
    try:
      print("Create account {} with {} as email".format(accountName, accountEmail))
      create_account_response = org_client.create_account(
        Email=accountEmail, 
        AccountName=accountName,
        IamUserAccessToBilling=accessToBilling
      )
      while(True):
        account_status = org_client.describe_create_account_status(
          CreateAccountRequestId=create_account_response['CreateAccountStatus']['Id']
        )
        print(account_status['CreateAccountStatus']['State'])
        if account_status['CreateAccountStatus']['State'] == 'SUCCEEDED':
          break
        elif account_status['CreateAccountStatus']['State'] == 'FAILED':
          print("Account Creation Failed: {}".format(account_status['CreateAccountStatus']['FailureReason']))
          sys.exit(1)
        else: 
          # is "IN_PROGRESS"
          time.sleep(5)


      while(awsAccountId is None):
          print("Waiting for account id")
          time.sleep(5)
          create_account_status_response = org_client.describe_create_account_status(
            CreateAccountRequestId=create_account_response.get('CreateAccountStatus').get('Id')
          )
          awsAccountId = create_account_status_response.get('CreateAccountStatus').get('AccountId')
      
      print("acct_id = {}".format(awsAccountId))

    except Exception as e:
      print("ERROR: {}".format(e))
      delete_respond_cloudformation(
        event, 
        "FAILED", 
        "Create Error: {}".format(e))

    print("move_start")
    try:
      print("AccountId = {}".format(awsAccountId))
      print("SourceParentId = {}".format(rootOrgId))
      print("DestinationParentId = {}".format(targetOrgId))
      move_response = org_client.move_account(
        AccountId=awsAccountId,
        SourceParentId=rootOrgId,
        DestinationParentId=targetOrgId
      )

    except Exception as e:
      print("ERROR: {}".format(e))
      delete_respond_cloudformation(
        event, 
        "FAILED", 
        "Move Error: {}".format(e))

    print("assume2 start")
    try:
      org_sts_response = org_sts_client.assume_role(
        RoleArn='arn:aws:iam::{}:role/OrganizationAccountAccessRole'.format(awsAccountId),
        RoleSessionName=orgSessionName
      )

      target_client = boto3.client(
          'iam', 
          aws_access_key_id=org_sts_response['Credentials']['AccessKeyId'],
          aws_secret_access_key=org_sts_response['Credentials']['SecretAccessKey'], 
          aws_session_token=org_sts_response['Credentials']['SessionToken'],
          region_name='us-east-1'
        )

    except Exception as e:
      print("ERROR: {}".format(e))
      delete_respond_cloudformation(
        event, 
        "FAILED", 
        "Assume Error: {}".format(e))


    assume_role_policy = {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
              "AWS": "arn:aws:iam::{}:root".format(turbotMasterAccount)
          },
          "Action": "sts:AssumeRole",
          "Condition": {
            "StringEquals": {
              "sts:ExternalId": turbotExternalId
            }
          }
        }
      ]   
    }

    print("role start")

    try:
      response = target_client.create_role(
        RoleName=accountRole,
        AssumeRolePolicyDocument=json.dumps(assume_role_policy),
        Description='Turbot Management Cross Account role'
      )

      accountRoleArn = response['Role']['Arn']

      response = target_client.attach_role_policy(
        RoleName=accountRole,
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
      )
    
    except Exception as e:
      print("ERROR: {}".format(e))
      delete_respond_cloudformation(
        event, 
        "FAILED", 
        "Create Role Error: {}".format(e))

    response = org_client.describe_account(
      AccountId=awsAccountId
    )

    print("Account created, attempting import")
    print(response)

    import_account(awsAccountId, accountRoleArn, turbotExternalId, parentId, endpoint, turbotAccessKey, turbotSecretKey)
    
    respond_cloudformation(
      event, 
      "SUCCESS", 
      { 
        "Message": "Account Created!", 
        "AccountID" : awsAccountId, 
      }
    )
  
  elif(event['RequestType'] == 'Update'):
    print("Template Update Requested")
    respond_cloudformation(event, "SUCCESS", { "Message": "Resources can not be updated via this template!" })

  elif(event['RequestType'] == 'Delete'):
    try:
      delete_respond_cloudformation(event, "SUCCESS", "Delete Request Initiated. Deleting Lambda Function. The account resource is not deleted.")
    except:
      print("Couldn't delete the lambda.")