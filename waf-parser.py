'''
    ============================================================================
    Title: Lambda Function - Web Application Firewall Condition Update Parser
    ============================================================================

    Description:
    ============
    This lambda function was written with the intent to parse log files produced
    by CloudFront and outputted to an S3 bucket. When CloudFront outputs a log
    file it causes an S3 event which triggers this lambda function. This
    function updates the WAF rules and saves the state and changes to DynamoDB.

    Pro Tips:
    =========
    - You can export a DynamoDB table as a CSV easily from the console.
    - TODO: DynamoDB funtionality hasn't been done yet.

    Instructions:
    =============
    1)  Define the user configurable constants below. These constants control
        how the lambda function operates. Each constant has a description
        included with it on it's usage.
    2)  If you're interested in how the function works, look at the
        "lambda_handler" function defined at the bottom of this file.

    Installation:
    =============
    TODO

    Links:
    ======
    - https://justinfox.me/articles/aws-waf-for-website-safety
    - https://github.com/awslabs/aws-waf-sample
'''
#===============================================================================
# User Configurable Constants
#===============================================================================
DYNAMODB_ENABLE = False
DYNAMODB_TABLE = "waf-rate-limiting"

WAF_ACL_NAME = "ratelimiting"
WAF_RULE_NAME = "Blacklisted-IPs"
WAF_CONDITION_NAME = "Blacklisted"

IP_WHITELIST = ['8.8.8.8/32','8.8.4.4/32']
IP_BLACKLIST = [{'Type': 'IPV4', 'Value': '10.0.0.0/8'},{'Type': 'IPV4', 'Value': '192.168.0.0/16'}]

IP_REQUEST_BLOCKCOUNT = 100

#===============================================================================
# Imported Libraries
#===============================================================================
import json
import boto3
import gzip


#===============================================================================
# Get S3 Object (gzip'd log file)
#===============================================================================
def get_logfile(bucket_name, key_name):
    #---------------------------------------------------------------------------
    #   Print debugging information, for CloudWatch logs.
    print("[get_logfile] :: Fetching log file from S3.")
    print("[get_logfile] :: Targeted S3 object is arn:aws:s3:::" + bucket_name + "/" + key_name)
    #---------------------------------------------------------------------------
    try:
        #-----------------------------------------------------------------------
        print("[get_logfile] :: Attempting to download object from S3.")
        #-----------------------------------------------------------------------
        local_file_path = '/tmp/' + key_name.split('/')[-1]
        s3 = boto3.client('s3')
        s3.download_file(bucket_name, key_name, local_file_path)
        #-----------------------------------------------------------------------
        print("[get_logfile] :: Download complete!")
        #-----------------------------------------------------------------------
    except Exception, e:
        #-----------------------------------------------------------------------
        print("[get_logfile] :: S3 exception encountered.")
        print("[get_logfile] :: Exception:" + str(e))
        #-----------------------------------------------------------------------
    try:
        #-----------------------------------------------------------------------
        print("[get_logfile] :: Attempting extract log file contents.")
        #-----------------------------------------------------------------------
        logs = []
        with gzip.open(local_file_path,'r') as content:
            for line in content:
                try:
                    if line.startswith('#'):
                        continue
                    line_data = line.split('\t')
                    processed = {'date':line_data[0], 'time' : line_data[1], 'edge_location':line_data[2], 'ip':line_data[4], 'http_method':line_data[5], 'url':line_data[9]+line_data[7], 'response_code':line_data[8]}
                    logs.append(processed)
                except Exception, e:
                    #-----------------------------------------------------------
                    print("[get_logfile] :: Extraction exception encountered.")
                    print("[get_logfile] :: Exception: " + str(e))
                    #-----------------------------------------------------------
        #-----------------------------------------------------------------------
        print("[get_logfile] :: Extraction of log file contents complete.")
        #-----------------------------------------------------------------------
    except Exception, e:
        #-----------------------------------------------------------------------
        print("[get_logfile] :: Gzip extraction exception encountered.")
        print("[get_logfile] :: Exception:" + str(e))
        #-----------------------------------------------------------------------
    return logs


#===============================================================================
# Create IP lists for blocking/removing from the WAF ip sets
#===============================================================================
def create_ip_list(logs, waf_ips):
    #---------------------------------------------------------------------------
    #   Print debugging information, for CloudWatch logs.
    print("[create_ip_list] :: Starting to process log files for ip set configuration.")
    #---------------------------------------------------------------------------
    block_list = []
    remove_list = []
    unique_ips = []
    all_ips = []
    for line in logs:
        if unique_ips.count(line['ip']) == 0:
            unique_ips.append(line['ip'])
        all_ips.append(line['ip'])
    for ip in unique_ips:
        if all_ips.count(ip) > IP_REQUEST_BLOCKCOUNT and ip not in IP_WHITELIST:
            block_list.append({ 'Type': 'IPV4', 'Value': ip })
    for ip_entry in IP_BLACKLIST:
        block_list.append(ip_entry)
    for ip_entry in IP_WHITELIST:
        remove_list.append({ 'Type': 'IPV4', 'Value': ip_entry })
    for ip_entry in waf_ips:
        if ip_entry not in block_list:
            remove_list.append(ip_entry)
    #---------------------------------------------------------------------------
    print("[create_ip_list] :: IP lists are created.")
    #---------------------------------------------------------------------------
    return block_list, remove_list


#===============================================================================
# Get WAF Status
#===============================================================================
def get_waf(waf_name, rule_name, condition_name):
    #---------------------------------------------------------------------------
    #   Print debugging information, for CloudWatch logs.
    print("[get_waf] :: Fetching WAF status.")
    #---------------------------------------------------------------------------
    try:
        #   Connect to the AWS WAF service.
        waf = boto3.client('waf')
        #   Get a list of current WAF rules, and find the one desired.
        acls = waf.list_web_acls(Limit=100)
        for acl in acls['WebACLs']:
            if acl['Name'] == waf_name:
                acl_id = acl['WebACLId']
        #   Get details about the WAF ACL using the discovered ACL ID.
        acl_details = waf.get_web_acl(WebACLId=acl_id)
        #   Locate our required WAF rule.
        rules = waf.list_rules(Limit=100)
        for rule in rules['Rules']:
            if rule['Name'] == rule_name:
                rule_id = rule['RuleId']
        #   Get details about the WAF rule using the discovered rule ID.
        rule_details = waf.get_rule(RuleId=rule_id)
        #   Locate our required WAF condition.
        ip_sets = waf.list_ip_sets(Limit=100)
        for ip_set in ip_sets['IPSets']:
            if ip_set['Name'] == condition_name:
                ip_set_id = ip_set['IPSetId']
        #   Get details about the WAF condition using the discovered ID.
        condition_details = waf.get_ip_set(IPSetId=ip_set_id)
        #   Get current IP statuses.
        ips = condition_details['IPSet']['IPSetDescriptors']
    except Exception, e:
        #-----------------------------------------------------------------------
        print("[get_waf] :: WAF exception encountered.")
        print("[get_waf] :: Exception: " + str(e))
        #-----------------------------------------------------------------------
    return acl_details, rule_details, condition_details, ips


#===============================================================================
# Update WAF Status
#===============================================================================
def update_waf(waf_condition_details, block_list, remove_list):
    #---------------------------------------------------------------------------
    #   Print debugging information, for CloudWatch logs.
    print("[update_waf] :: Updating WAF condition ip_set.")
    #---------------------------------------------------------------------------
    try:
        #   Create an properly formatted update request.
        updates = []
        for ip_set in block_list:
            updates.append({'Action': 'INSERT','IPSetDescriptor': ip_set})
        #for ip_set in remove_list:
        #    update_removes.append({'Action': 'DELETE','IPSetDescriptor': ip_set})
        #   Connect to the WAF service
        waf = boto3.client('waf')
        #   In order to make a change to a WAF configuration, we need a change
        #   token.
        change_token = waf.get_change_token()['ChangeToken']
        update_request = waf.update_ip_set(
            IPSetId=waf_condition_details['IPSet']['IPSetId'],
            ChangeToken=change_token,
            Updates=updates
        )['ChangeToken']
        #-----------------------------------------------------------------------
        print("[update_waf] :: WAF status token is " + update_request + ".")
        #-----------------------------------------------------------------------
        return update_request
    except Exception, e:
        #-----------------------------------------------------------------------
        print("[update_waf] :: WAF update exception encountered.")
        print("[update_waf] :: Exception: " + str(e))
        #-----------------------------------------------------------------------


#===============================================================================
# Lambda Handler
#===============================================================================
def lambda_handler(event, context):
    #---------------------------------------------------------------------------
    #   Print debugging information, for CloudWatch logs.
    print("[lambda_handler] :: Initializing lambda function.")
    print("[lambda_handler] :: Received event: " + json.dumps(event))
    #---------------------------------------------------------------------------
    object = json.loads(json.dumps(event))
    s3_bucket_name = object['Records'][0]['s3']['bucket']['name']
    s3_object_name = object['Records'][0]['s3']['object']['key']
    #   Get the S3 log file
    logs = get_logfile(s3_bucket_name, s3_object_name)
    #   Get current status from WAF
    waf_acl_details, waf_rule_details, waf_condition_details, waf_ips = get_waf(WAF_ACL_NAME, WAF_RULE_NAME, WAF_CONDITION_NAME)
    #   Blocking logic
    block_list, remove_list = create_ip_list(logs, waf_ips)
    #   Set WAF condition
    waf_status = update_waf(waf_condition_details, block_list, remove_list)
    #   If enabled, get current DynamoDB status, and update with new records.
    #if DYNAMODB_ENABLE:
    #    dynamodb = get_dynamo(DYNAMODB_TABLE)
    #   Save state to DynamoDB
    #---------------------------------------------------------------------------
    print("[lambda_handler] :: Exiting lambda function now.")
    #---------------------------------------------------------------------------
