import os


class AwsCredentials:
    def __init__(self, access_key_id: str, secret_access_key: str, region: str,
                 sms_sender_id: str, default_country_code: str):
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.region = region
        self.sms_sender_id = sms_sender_id
        self.sms_default_country_code = default_country_code


def get_aws_credentials():
    cred = AwsCredentials(
        os.environ.get('AWS_ACCESS_KEY_ID'),
        os.environ.get('AWS_SECRET_ACCESS_KEY'),
        os.environ.get('AWS_REGION'),
        os.environ.get('AWS_SMS_SENDER_ID'),
        os.environ.get('AWS_SMS_DEFAULT_COUNTRY_CODE')
    )
    missing_envs = []
    if not cred.access_key_id:
        missing_envs.append('AWS_ACCESS_KEY_ID')
    if not cred.secret_access_key:
        missing_envs.append('AWS_SECRET_ACCESS_KEY')
    if not cred.region:
        missing_envs.append('AWS_REGION')
    if not cred.sms_sender_id:
        missing_envs.append('AWS_SMS_SENDER_ID')
    if not cred.sms_default_country_code:
        missing_envs.append('AWS_SMS_DEFAULT_COUNTRY_CODE')
    if missing_envs:
        err = 'Missing environment variables: {}'.format(', '.join(missing_envs))
        raise Exception(err)
    return cred


def aws_send_sms(creds: AwsCredentials, phone_number, message):
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
        print("Published message to %s." % phone_number)
        return message_id
    except ClientError as e:
        err = "AWS SMS error:" + str(e)
        raise Error(err)
