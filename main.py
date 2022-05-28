import os, re
from flask import jsonify, request

from aws_utils import get_aws_credentials, aws_send_sms
from ldap_utils import list_users_with_phone_num, ldap_fetch_user_mobile, get_ldap_args_from_env


def validate_msisdn(msisdn: str, default_country_code: str):
    msisdn = re.sub(r'\s+', '', msisdn) # Remove whitespaces
    msisdn = re.sub(r'^00', '+', msisdn) # Replace 00 with +
    if msisdn.startswith('0'):
        msisdn = default_country_code + msisdn[1:]
    if not re.match(r'^[+\-0-9]+$', msisdn):
        raise Exception('Invalid phone number')
    return msisdn


def main():

    aws_creds, ldap_args = None, None
    try:
        ldap_args = get_ldap_args_from_env()
        aws_creds = get_aws_credentials()
    except Exception as e:
        print(str(e))
        return 1

    # Start the flask app
    from flask import Flask, render_template
    template_dir = os.path.abspath('htdocs')
    app = Flask(__name__, template_folder=template_dir)

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/users')
    def users():
        return render_template('users.html')

    @app.route('/users_json')
    def users_json():
        try:
            res = jsonify(list_users_with_phone_num(ldap_args))
        except Exception as e:
            res = jsonify({'error': str(e)})
        return res

    @app.route('/send_sms', methods=['POST'])
    def send_sms():
        try:
            data = request.get_json(force=True)

            # Check input
            if 'guid' not in data or 'message' not in data or not data['guid'] or not data['message']:
                raise Exception('Missing parameters')
            data['message'] = data['message'][:160]

            # Fetch user's mobile phone from LDAP based on objectGUID
            mobile = ldap_fetch_user_mobile(ldap_args, user_guid=data['guid'])
            mobile = validate_msisdn(mobile, aws_creds.sms_default_country_code)
            aws_send_sms(aws_creds, mobile, data['message'])

            res = jsonify({'success': True})
        except Exception as e:
            res = jsonify({'error': str(e)})
        return res

    app.run(debug=True)


if __name__ == '__main__':
    main()
