#!/usr/bin/env python3

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
import base64
import time
import os
import logging
import time


logger = logging.getLogger()
logger.setLevel(logging.INFO)
# Quiet Boto3
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)

# Deploy Guard Duty across all child accounts to the payer account
# Process documented here: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html#guardduty_become_api

DEFAULT_MESSAGE='Parent Account is enabling GuardDuty. No Action Required.'

DRY_RUN=False

def create_parent_detector(gd_client, region):
    if DRY_RUN:
        logger.info(
            f"Need to create a Detector in {region} for the GuardDuty Master account"
        )
        return(None)

    logger.info(
        f"Creating a Detector in {region} for the GuardDuty Master account"
    )
    try:
        response = gd_client.create_detector(Enable=True)
        return(response['DetectorId'])
    except ClientError as e:
        logger.error(f"Failed to create detector in {region}. Aborting...")
        exit(1)

def get_all_members(region, gd_client, detector_id):
    output = {}
    response = gd_client.list_members(DetectorId=detector_id, MaxResults=50)
    while 'NextToken' in response:
        for a in response['Members']:
            # Convert to a lookup table
            output[a['AccountId']] = a
        response = gd_client.list_members(DetectorId=detector_id, MaxResults=50, NextToken=response['NextToken'])
    for a in response['Members']:
        # Convert to a lookup table
        output[a['AccountId']] = a

    return(output)

def process_region(args, region):
    print(f"Processing Region {region}")
    gd_client = boto3.client('guardduty', region_name=region)
    org_client = boto3.client('organizations')

    # An account can only have one detector per region
    try:
        response = gd_client.list_detectors()
        if len(response['DetectorIds']) == 0:
            # We better create one
            detector_id = create_parent_detector(gd_client, region)
        else:
            detector_id = response['DetectorIds'][0]
    except ClientError as e:
        logger.error(
            f"Unable to list detectors in region {region}. Skipping this region."
        )
        return(False)
    except EndpointConnectionError as e:
        logger.error(
            f"Unable to list detectors in region {region}. Skipping this region."
        )
        return(False)


    gd_status = get_all_members(region, gd_client, detector_id)

    payer_account_list = get_consolidated_billing_subaccounts(args)
    for a in payer_account_list:
        if a['Status'] != "ACTIVE":
            continue
        if a['Id'] not in gd_status:
            if DRY_RUN:
                print(f"Need to enable GuardDuty for {a['Name']}({a['Id']})")
            else:
                print(f"Enabling GuardDuty for {a['Name']}({a['Id']})")
            if not args.accept_only:
                invite_account(a, detector_id, region, args.message)
                time.sleep(3)
            accept_invite(a, args.assume_role, region)
            # exit(1)
            continue
        if gd_status[a['Id']]['RelationshipStatus'] == "Enabled":
            # print("{}({}) is already enabled for GuardDuty in {}".format(a['Name'], a['Id'], region))
            continue
        print(
            f"{a['Name']}({a['Id']}) is in unexpected state {gd_status[a['Id']]['RelationshipStatus']} for GuardDuty in {region}"
        )
        return()

def invite_account(account, detector_id, region, message):
    if DRY_RUN:
        print(
            f"Need to Invite {account['Name']}({account['Id']}) to this GuardDuty Master"
        )
        return(None)
    client = boto3.client('guardduty', region_name=region)
    print(f"Inviting {account['Name']}({account['Id']}) to this GuardDuty Master")
    response = client.create_members(
        AccountDetails=[
            {
                'AccountId': account['Id'],
                'Email': account['Email']
            },
        ],
        DetectorId=detector_id
    )
    response = client.invite_members(
        AccountIds=[ account['Id'] ],
        DetectorId=detector_id,
        DisableEmailNotification=True
    )

def accept_invite(account, role_name, region):
    if DRY_RUN:
        print(f"Need to accept invite in {account['Name']}({account['Id']})")
        return(None)
    print(f"Accepting invite in {account['Name']}({account['Id']})")
    organization_role_arn = "arn:aws:iam::{}:role/{}"
    session_creds = get_creds(organization_role_arn.format(account['Id'], role_name))
    if session_creds is False:
        print(
            f"Unable to assume role into {account['Name']}({account['Id']}) to accept the invite"
        )
        return(False)
    child_client = boto3.client('guardduty', region_name=region,
        aws_access_key_id = session_creds['AccessKeyId'],
        aws_secret_access_key = session_creds['SecretAccessKey'],
        aws_session_token = session_creds['SessionToken']
        )
    response = child_client.list_detectors()
    if len(response['DetectorIds']) == 0:
        response = child_client.create_detector(Enable=True)
        detector_id = response['DetectorId']
    else:
        detector_id = response['DetectorIds'][0]
    response = child_client.list_invitations()
    for i in response['Invitations']:
        response = child_client.accept_invitation(
            DetectorId=detector_id,
            InvitationId=i['InvitationId'],
            MasterId=i['AccountId']
            )

def get_creds(role_arn):
    client = boto3.client('sts')
    try:
        session = client.assume_role(RoleArn=role_arn, RoleSessionName="EnableGuardDuty")
        return(session['Credentials'])
    except Exception as e:
        print(f"Failed to assume role {role_arn}: {e}")
        return(False)
# end get_payer_creds()

def get_consolidated_billing_subaccounts(args):
    # Returns: [
    #         {
    #             'Id': 'string',
    #             'Arn': 'string',
    #             'Email': 'string',
    #             'Name': 'string',
    #             'Status': 'ACTIVE'|'SUSPENDED',
    #             'JoinedMethod': 'INVITED'|'CREATED',
    #             'JoinedTimestamp': datetime(2015, 1, 1)
    #         },
    #     ],
    if args.payer_arn is not None:
        payer_creds = get_creds(args.payer_arn)
        if payer_creds == False:
            print(f"Unable to assume role in payer {args.payer_arn}")
            exit(1)

        org_client = boto3.client('organizations',
            aws_access_key_id = payer_creds['AccessKeyId'],
            aws_secret_access_key = payer_creds['SecretAccessKey'],
            aws_session_token = payer_creds['SessionToken']
        )
    else:
        org_client = boto3.client('organizations')

    output = []

    try:
        # If we're only supposed to do one account, just get that from the payer and returnn
        if args.account_id:
            response = org_client.describe_account( AccountId=args.account_id )
            output.append(response['Account'])
            return(output)

        # Otherwise, gotta catch 'em all
        response = org_client.list_accounts( MaxResults=20 )
        while 'NextToken' in response :
            output = output + response['Accounts']
            response = org_client.list_accounts( MaxResults=20, NextToken=response['NextToken'] )

        return output + response['Accounts']
    except ClientError as e:
        print(
            f"Unable to get account details from Organizational Parent: {e}.\nAborting..."
        )
        exit(1)

def do_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--error", help="print error info only", action='store_true')


    #
    # Required
    #
    parser.add_argument("--account_id", help="AWS Account ID")
    parser.add_argument("--payer_arn", help="Assume this role to get the list of accounts")
    parser.add_argument("--assume_role", help="Name of the Role to assume in Child Accounts", default="OrganizationAccountAccessRole")
    parser.add_argument("--region", help="Only run in this region", default="ALL")

    parser.add_argument("--message", help="Custom Message sent to child as part of invite", default=DEFAULT_MESSAGE)
    parser.add_argument("--accept_only", help="Accept existing invite again", action='store_true')
    parser.add_argument("--dry-run", help="Only print what needs to happen", action='store_true')



    args = parser.parse_args()

    # Logging idea stolen from: https://docs.python.org/3/howto/logging.html#configuring-logging
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    if args.debug:
        ch.setLevel(logging.DEBUG)
    elif args.error:
        ch.setLevel(logging.ERROR)
    else:
        ch.setLevel(logging.INFO)
    # create formatter
    # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    # add formatter to ch
    ch.setFormatter(formatter)
    # add ch to logger
    logger.addHandler(ch)

    # if not hasattr(args, 'environment_id'):
    #     print("Must specify --environment_id")
    #     exit(1)

    return(args)



if __name__ == '__main__':
    args = do_args()

    if args.dry_run:
        print("Only doing a DryRun...")
        DRY_RUN = True

    regions = []
    if args.region == "ALL":
        ec2 = boto3.client('ec2')
        response = ec2.describe_regions()
        regions.extend(r['RegionName'] for r in response['Regions'])
    else:
        regions.append(args.region)

    for r in regions:
        process_region(args, r)


