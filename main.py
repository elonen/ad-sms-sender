import re, sys
from flask import jsonify, request
from flask_httpauth import HTTPBasicAuth

from aws_utils import *
from ldap_utils import *

from cachetools import cached, TTLCache

def validate_msisdn(msisdn: str, default_country_code: str):
    msisdn = re.sub(r'\s+', '', msisdn) # Remove whitespaces
    msisdn = re.sub(r'^00', '+', msisdn) # Replace 00 with +
    if msisdn.startswith('0'):
        msisdn = default_country_code + msisdn[1:]
    if not re.match(r'^[+\-0-9]+$', msisdn):
        raise Exception('Invalid phone number')
    return msisdn


def main():
    # Start the flask app
    from flask import Flask, render_template
    template_dir = os.path.abspath('htdocs')
    app = Flask(__name__, template_folder=template_dir)
    auth = HTTPBasicAuth()

    aws_conf, ldap_args = None, None
    try:
        ldap_args = get_ldap_args_from_env(app.logger)
        aws_conf = get_aws_credentials(app.logger)
    except Exception as e:
        print(str(e), file=sys.stderr)
        return 1

    # Authentication and Authorization against AD/LDAP users

    @auth.verify_password
    @cached(cache=TTLCache(maxsize=1024, ttl=30))
    def verify_password(username, password):
        if test_ldap_user_password(ldap_args, username, password):
            return username

    @auth.get_user_roles
    @cached(cache=TTLCache(maxsize=1024, ttl=30))
    def get_user_roles(username):
        roles = []
        if ldap_test_user_group_membership(ldap_args, username, ldap_args.auth_sender_group_dn):
            roles = ['sender', 'viewer']
        elif ldap_test_user_group_membership(ldap_args, username, ldap_args.auth_viewer_group_dn):
            roles = ['viewer']
        return roles

    @auth.error_handler
    def auth_error(status):
        err = f"Status {status}: Incorrect username/password or missing privileges. "\
              "Your Active Directory accounts needs to be a member of group<br/> "\
              f"<code>{ldap_args.auth_viewer_group_dn}</code> to view phonebook, and<br/>" \
              f"<code>{ldap_args.auth_sender_group_dn}</code> to send SMS."
        return render_template('index.html', login_error_message=err)


    # HTTP route handlers

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/users')
    @auth.login_required(role=['sender', 'viewer'])
    def users():
        return render_template(
            'users.html',
            sms_enabled=('sender' in get_user_roles(auth.current_user())),
            gui_mobile_field_name=ldap_args.gui_label_mobile,
            gui_home_phone_field_name=ldap_args.gui_label_home_phone
        )

    @app.route('/users_json')
    @auth.login_required(role=['sender', 'viewer'])
    def users_json():
        try:
            ul = list_users_with_phone_num(ldap_args)
            ul.sort(key=lambda x: x['user'])
            res = jsonify(ul)
        except Exception as e:
            res = jsonify({'error': str(e)})
            app.logger.error(e, exc_info=True)
        return res


    @app.route('/send_sms', methods=['POST'])
    @auth.login_required(role=['sender'])
    def send_sms():
        try:
            data = request.get_json(force=True)

            # Check input
            if 'guid' not in data or 'message' not in data or not data['guid'] or not data['message']:
                raise Exception('Missing parameters')
            data['message'] = data['message'][:160]

            for p in data['phone_fields']:
                assert p in ['mobile', 'homePhone'], 'Invalid phone field'

            # Fetch user's mobile phone from LDAP based on objectGUID
            msg_id = None
            for fld in data['phone_fields']:
                mobile = ldap_fetch_user_mobile(ldap_args, user_guid=data['guid'], attr=fld)
                if mobile:
                    mobile = validate_msisdn(mobile, aws_conf.sms_default_country_code)
                    app.logger.info(f"Sending SMS to {mobile}...")
                    msg_id = aws_send_sms(aws_conf, mobile, data['message'])

            if msg_id is None:
                raise Exception('No phone number found')

            res = jsonify({'success': True, 'message_id': msg_id})

        except Exception as e:
            res = jsonify({'error': str(e)})
        return res


    @app.route('/latest_report_ts', methods=['GET'])
    @auth.login_required(role=['sender'])
    def latest_report_ts():
        try:
            ts = get_sms_latest_delivery_timestamp(aws_conf)
            if ts is not None:
                return jsonify({'timestamp': ts})
            else:
                return ('Delivery reporting log group not configured.', 404)
        except Exception as e:
            res = jsonify({'error': str(e)})
            return (res, 500)


    @app.route('/delivery_status', methods=['POST'])
    @auth.login_required(role=['sender'])
    def delivery_status():
        try:
            data = request.get_json(force=True)
            if 'message_ids' not in data or not data['message_ids']:
                raise Exception('Missing parameters')
            start_ts = 0
            if 'start_ts' in data and data['start_ts']:
                start_ts = int(data['start_ts'])

            dres = get_sms_check_delivery_status(aws_conf, data['message_ids'], start_ts)
            if dres is not None:
                return jsonify(dres)
            else:
                return ('Delivery reporting not available.', 404)

        except Exception as e:
            res = jsonify({'error': str(e)})
            return (res, 500)


    app.run(host='127.0.0.1', port=5000)


if __name__ == '__main__':
    main()
