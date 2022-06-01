import os
from logging import Logger


class AwsSettings:
    access_key_id: str
    secret_access_key: str
    region: str
    sms_sender_id: str
    sms_default_country_code: str
    log: Logger


def get_aws_credentials(log) -> AwsSettings:
    """
    Get AWS credentials from environment variables.
    :param log: Logger object
    :return: AwsSettings object
    """
    missing_envs = []

    def env(name: str) -> str:
        nonlocal missing_envs
        v = os.environ.get(name)
        if not v:
            missing_envs.append(name)
        return v

    conf = AwsSettings()
    conf.access_key_id = env('AWS_ACCESS_KEY_ID')
    conf.secret_access_key = env('AWS_SECRET_ACCESS_KEY')
    conf.region = env('AWS_REGION')
    conf.sms_sender_id = env('AWS_SMS_SENDER_ID')
    conf.sms_default_country_code = env('AWS_SMS_DEFAULT_COUNTRY_CODE')
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
    from boto3.session import Session
    from botocore.exceptions import ClientError

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
