from dataclasses import dataclass
import json
import os
from logging import Logger
from typing import Tuple, Union

from boto3.session import Session
from botocore.exceptions import ClientError
import boto3

from cachetools import TTLCache, cached
from threading import Lock

class AwsSettings:
    access_key_id: str
    secret_access_key: str
    region: str
    sms_sender_id: str
    sms_default_country_code: str
    sms_cloudwatch_log_group: str
    log: Logger


def get_aws_credentials(log) -> AwsSettings:
    """
    Get AWS credentials from environment variables.
    :param log: Logger object
    :return: AwsSettings object
    """
    missing_envs = []

    def env(name: str, default=None) -> str:
        nonlocal missing_envs
        v = os.environ.get(name)
        if not v:
            if default is not None:
                return default
            missing_envs.append(name)
        return v or ''

    conf = AwsSettings()
    conf.access_key_id = env('AWS_ACCESS_KEY_ID')
    conf.secret_access_key = env('AWS_SECRET_ACCESS_KEY')
    conf.region = env('AWS_REGION')
    conf.sms_sender_id = env('AWS_SMS_SENDER_ID')
    conf.sms_default_country_code = env('AWS_SMS_DEFAULT_COUNTRY_CODE')
    conf.sms_cloudwatch_log_group = env('AWS_SMS_CLOUDWATCH_LOG_GROUP', default='')
    conf.log = log

    if missing_envs:
        raise Exception('Missing environment variables: {}'.format(', '.join(missing_envs)))
    return conf


def aws_send_sms(creds: AwsSettings, phone_number: str, message: str) -> str:
    """
    Send an SMS to a phone number.
    :return: ID of the message.
    :raise: Exception if the message could not be published.
    """
    try:
        session = Session(aws_access_key_id=creds.access_key_id,
                          aws_secret_access_key=creds.secret_access_key,
                          region_name=creds.region)

        sns_resource = session.resource('sns')

        sms_attribs = {'AWS.SNS.SMS.SenderID': {'DataType': 'String', 'StringValue': creds.sms_sender_id}}
        response = sns_resource.meta.client.publish(
            PhoneNumber=phone_number, Message=message,
            MessageAttributes=sms_attribs)
        message_id = response['MessageId']

        creds.log.info(f"Published message to {phone_number}, message_id: {message_id}.")
        return message_id

    except ClientError as e:
        err = "AWS SMS error:" + str(e)
        raise Exception(err)


@cached(cache=TTLCache(maxsize=8, ttl=2), lock=Lock())   # Cache for 2 seconds, this is a rate-limited operation
def _get_sms_delivery_streams(creds: AwsSettings) -> Tuple[list, boto3.client]:
    """
    Get all log streams for the SMS delivery log group.
    :return: List of log streams, and the boto3 client object.
    :raise: Exception if the logs could not be read (e.g. due to missing permissions).
    """
    session = Session(aws_access_key_id=creds.access_key_id,
                      aws_secret_access_key=creds.secret_access_key,
                      region_name=creds.region)
    logs_client = session.client('logs')
    res = []

    # Get first page of log streams
    streams = logs_client.describe_log_streams(
        logGroupName=creds.sms_cloudwatch_log_group,
        orderBy='LastEventTime',
        descending=True
    )
    assert 'logStreams' in streams, "No log streams found"
    res.extend(streams['logStreams'])

    # Paginate through all log streams
    while token := streams.get('nextToken'):
        streams = logs_client.describe_log_streams(
            logGroupName=creds.sms_cloudwatch_log_group,
            orderBy='LastEventTime',
            descending=True,
            nextToken=token
        )
        assert 'logStreams' in streams, "No log streams found"
        res.extend(streams['logStreams'])

    assert len(streams) < 32, "Too many log streams found, refusing to process events. Set up a cleaner."

    return res, logs_client


def get_sms_latest_delivery_timestamp(creds: AwsSettings) -> Union[int, None]:
    """
    Get the timestamp of the latest SMS delivery log.
    This is used to avoid re-reading obsolete logs.

    :return: Timestamp, or None if creds.sms_cloudwatch_log_group is not set.
    :raise: Exception if the logs could not be read (e.g. due to missing permissions).
    """
    if not creds.sms_cloudwatch_log_group:
        return None

    streams, logs_client = _get_sms_delivery_streams(creds)
    latest_ts = 0
    for stm in streams:
        events = logs_client.get_log_events(
            logGroupName=creds.sms_cloudwatch_log_group,
            logStreamName=stm['logStreamName'],
            limit=1,
        )
        if 'events' in events and events['events']:
            latest_ts = max(latest_ts, events['events'][0]['timestamp'])
    return latest_ts


@dataclass
class SmsDeliveryStatus:
    delivered: bool
    reason: str
    timestamp: int

def get_sms_check_delivery_status(creds: AwsSettings, message_ids: list, start_ts: int) -> Union[dict[str, SmsDeliveryStatus], None]:
    """
    Get delivery status of given SMS messages.
    :param message_ids: List of message IDs to look for
    :param start_ts: Timestamp of the earliest log event to read
    :return: Dictionary of message ID -> SmsDeliveryStatus, or None if creds.sms_cloudwatch_log_group is not set.
    :raise: Exception if the logs could not be read (e.g. due to missing permissions).
    """
    if not creds.sms_cloudwatch_log_group:
        return None
    streams, logs_client = _get_sms_delivery_streams(creds)

    def _get_events(**args) -> list[dict]:
        # Paginate through all log events
        events = logs_client.get_log_events(**args)
        res = events['events']
        while token := events.get('nextForwardToken'):
            if not events.get('events'):
                break
            events = logs_client.get_log_events(**args, nextToken=token)
            res += events['events']
            assert len(res) < 4096, "Too many log events found, stopping pagination. Something is likely wrong."
        return res

    res = {}
    for stm in streams:
        new_events = _get_events(
            logGroupName=creds.sms_cloudwatch_log_group,
            logStreamName=stm['logStreamName'],
            startFromHead=True,
            startTime=start_ts,
        )
        for evt in new_events:
            message = json.loads(evt['message'])
            for id in message_ids:
                if id in message['notification']['messageId']:
                    delivered = message['status'] == 'SUCCESS'
                    res[id] = SmsDeliveryStatus(
                        delivered=delivered,
                        reason=message['delivery']['providerResponse'],
                        timestamp=message['notification']['timestamp']
                    )
                    creds.log.info(f"Found delivery status for message ID {id}: {res[id]}")
                    break
    return res
