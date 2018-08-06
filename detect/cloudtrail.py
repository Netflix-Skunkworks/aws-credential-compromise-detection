from datetime import datetime, timedelta
import gzip
import ipaddress
import json
import time

from detect import log


def ip_in_cidr(ip, cidr):
    """Check to see if the provided IP address is in the provided CIDR block"""
    return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)


def ip_in_whitelist(whitelist, ip):
    """Check the whitelist where we allow calls to come from"""
    for cidr in whitelist:
        if ip_in_cidr(ip, cidr):
            return True

    return False


def is_ip_private(ip):
    """Check the whitelist where we allow calls to come from"""
    private = ['100.64.0.0/10', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']

    for cidr in private:
        if ip_in_cidr(ip, cidr):
            return True

    return False


def detect_off_instance_cloudtrail(config, files):
    """Detect off use of credential off instance"""
    bad_calls = []
    api_calls = {}
    associate_ips = []

    for file in sorted(files):
        f = None
        log.info('Processing file: {}'.format(file))

        if file.endswith('.gz'):
            f = gzip.open(file, 'r')
        else:
            f = open(file, 'r')

        try:
            cloudtrail = json.load(f)
        except Exception as e:
            log.error('Invalid JSON File: {} - {}'.format(file, e))
            continue

        records = sorted(cloudtrail['Records'], key=lambda x: datetime.strptime(x['eventTime'], '%Y-%m-%dT%H:%M:%SZ'), reverse=False)

        for record in records:

            try:
                if record['eventName'].lower() == 'assumerole' and record['sourceIPAddress'] == 'ec2.amazonaws.com':

                    session_name = record['requestParameters']['roleSessionName']
                    arn = record['requestParameters']['roleArn']
                    account = record['requestParameters']['roleArn'].split(':')[4]
                    role = record['requestParameters']['roleArn'].split('/')[-1]

                    assume_role_session = 'arn:aws:sts::{}:assumed-role/{}/{}'.format(account, role, session_name)

                    if not api_calls.get(session_name, None):
                        api_calls[session_name] = {
                            'source_ip': [],
                            'arn': assume_role_session,
                            'ttl': int(time.time() + 28800)
                        }
                    else:
                        # Set a TTL.  This is most useful in DynamoDB
                        api_calls[session_name]['ttl'] = int(time.time() + 28800)

                if record['userIdentity'].get('type', '') == 'AssumedRole':
                    session = record['userIdentity']['arn'].split('/')[-1]
                    if api_calls.get(session, None):
                        # Check to see if this is a call that would attach a new ENI or IP to the instance
                        if (record['eventName'].lower() == 'attachnetworkinterface' or record['eventName'].lower() == 'associateaddress') and not record.get('errorMessage', None):
                            log.info('Potential for a new IP to be seen: {}'.format(record['userIdentity']['arn']))

                            if record['requestParameters']['instanceId'] == session:
                                associate_ips.append(session)

                        # Check to see if the IP is in the whitelist first before we decide to process anything
                        # if it is, then we can ignore the call
                        if 'amazonaws' not in record['sourceIPAddress'] and not ip_in_whitelist(config.get('whitelist_ips', []), record['sourceIPAddress']):
                            if len(api_calls[session].get('source_ip', [])) == 0:
                                # This is the first call that we've seen since the assume role
                                # First IP, let's add it to the list, we don't care if it's private
                                # or public at this point
                                api_calls[session]['source_ip'].append(record['sourceIPAddress'])
                            else:
                                if record['sourceIPAddress'] not in api_calls[session].get('source_ip', []):
                                    # This IP is not in the current lock IP list
                                    # Check to see if this is a private IP
                                    if is_ip_private(record['sourceIPAddress']):
                                        # First check to see if there is already another private IP.  We should
                                        # not have this ever
                                        for ip in api_calls[session].get('source_ip', []):
                                            if is_ip_private(ip):
                                                # Uh oh, another private IP, this shouldn't happen
                                                log.info('Compromised Credential: {} - Source IP: {}'.format(assume_role_session, record['sourceIPAddress']))
                                                log.debug(record)
                                                bad_calls.append(record)
                                        # This is the private IP for the instance communicating over a VPC endpoint
                                        api_calls[session]['source_ip'].append(record['sourceIPAddress'])
                                        continue
                                    # Check to see if we there was an API call to change the instance IP
                                    if session not in associate_ips:
                                        # Uh oh, alert!
                                        log.info('Compromised Credential: {} - Source IP: {}'.format(assume_role_session, record['sourceIPAddress']))
                                        log.debug(record)
                                        bad_calls.append(record)
                                    else:
                                        # We saw a new IP, but we expected this so removing the session from the allowed
                                        # change table
                                        log.debug('Removing allowed IP change for {}'.format(session))
                                        api_calls[session]['source_ip'].append(record['sourceIPAddress'])
                                        associate_ips.remove(session)
            except Exception as e:
                log.fatal('Unknown error on record - {}'.format(record))
                log.fatal('Error - {}'.format(e))

        # Close file object
        f.close()

    return bad_calls
