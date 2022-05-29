import os
import time
import ldap, ldap.filter


class LdapSettings:
    def __init__(self, server, base, bind_user, bind_password, auth_group_dn, default_domain, log):
        self.server = server
        self.base = base
        self.bind_user = bind_user
        self.bind_password = bind_password
        self.auth_group_dn = auth_group_dn
        self.default_domain = default_domain
        self.log = log


def get_ldap_args_from_env(log):
    """
    Get LDAP settings from environment variables.
    :param log: Logger object
    :return: LdapSettings object
    """
    server = os.environ.get('LDAP_SERVER')
    base = os.environ.get('LDAP_BASE')
    bind_user = os.environ.get('LDAP_BIND_USER')
    bind_password = os.environ.get('LDAP_BIND_PASS')
    auth_group_dn = os.environ.get('LDAP_AUTH_GROUP')
    default_domain = os.environ.get('LDAP_AUTH_DEFAULT_DOMAIN')

    if None in [server, base, bind_user, bind_password]:
        missing_envs = []
        if not server:
            missing_envs.append('LDAP_SERVER')
        if not base:
            missing_envs.append('LDAP_BASE')
        if not bind_user:
            missing_envs.append('LDAP_BIND_USER')
        if not bind_password:
            missing_envs.append('LDAP_BIND_PASS')
        if not auth_group_dn:
            missing_envs.append('LDAP_AUTH_GROUP')
        if not default_domain:
            missing_envs.append('LDAP_AUTH_DEFAULT_DOMAIN')

        err = 'Missing environment variables: {}'.format(', '.join(missing_envs))
        raise Exception(err)

    return LdapSettings(server, base, bind_user, bind_password,
                        auth_group_dn, default_domain, log)


def test_ldap_user_password(ldap_args: LdapSettings, user_account: str, password: str):
    """
    Test if a user can authenticate with a given password.
    This will append domain to the username if it's missing.

    :param ldap_args: LdapSettings object
    :param user_account: User account to test
    :param password: Password to test
    :return: True if the user can authenticate, False otherwise
    """
    # Append domain if not present
    user_account = user_account.strip()
    if '@' not in user_account:
        user_account = user_account + '@' + ldap_args.default_domain.strip(' @')
    ldap_args.log.info('Testing LDAP user password: ' + user_account)

    l = ldap.initialize(ldap_args.server)
    try:
        l.protocol_version = ldap.VERSION3
        l.simple_bind_s(user_account, password)
        ldap_args.log.info('LDAP user authenticated ok: ' + user_account)
        return True
    except ldap.INVALID_CREDENTIALS:
        ldap_args.log.warning('LDAP user authentication failed: ' + user_account)
        return False
    finally:
        l.unbind()


last_ldap_query_time = 0
last_ldap_query_result = None
ldap_cache_ttl = 15


def list_users_with_phone_num(ldap_args: LdapSettings):
    """
    Returns a list of users with a mobile number set in their AD account.
    :param ldap_args: LdapSettings object
    :return: list of users with mobile numbers and their GUIDs
    """
    # Return cached result if it's not too old
    global last_ldap_query_time
    global last_ldap_query_result
    if time.time() - last_ldap_query_time < ldap_cache_ttl:
        ldap_args.log.info('Using cached LDAP query result, from timestamp {}'.format(last_ldap_query_time))
        return last_ldap_query_result
    else:
        ldap_args.log.info('No fresh cached LDAP. Doing query.')

    # Connect
    l = ldap.initialize(ldap_args.server)
    l.protocol_version = ldap.VERSION3
    l.simple_bind_s(ldap_args.bind_user, ldap_args.bind_password)

    # Search for users with a mobile phone number
    ldap_filter = '(&(objectClass=person)(mobile=*))'
    attrs = ['cn', 'mobile', 'sAMAccountName', 'sn', 'objectGUID']
    ldap_args.log.debug('LDAP searching mobile phone users: ' + ldap_filter)
    ldap_result_id = l.search(ldap_args.base, ldap.SCOPE_SUBTREE, ldap_filter, attrs)
    result_set = []
    while 1:
        result_type, result_data = l.result(ldap_result_id, 0)
        if not result_data:
            break
        else:
            if result_type == ldap.RES_SEARCH_ENTRY:
                ldap_args.log.debug('LDAP user found: ' + str(result_data))
                result_set.append(result_data)

    l.unbind_s()  # Clean up

    # Format result
    res = [{
        'user': x[0][1]['sAMAccountName'][0].decode('utf-8'),
        'mobile': x[0][1]['mobile'][0].decode('utf-8'),
        'guid': x[0][1]['objectGUID'][0].hex()
    } for x in result_set]

    # Update cache
    last_ldap_query_time = time.time()
    last_ldap_query_result = res

    return res


def ldap_fetch_user_mobile(ldap_args: LdapSettings, user_guid: str):
    """
    Get mobile number of a user with a given GUID.
    :param ldap_args: LdapSettings object
    :param user_guid: GUID of the user
    :return: Mobile number of the user
    """
    all_users = list_users_with_phone_num(ldap_args)  # Note: underlying function caches the result
    for user in all_users:
        if user['guid'] == user_guid:
            return user['mobile']
    raise Exception('User not found')


def ldap_test_user_group_membership(ldap_args: LdapSettings, user_account: str, group_dn: str):
    """
    Test if a user is a member of an AD group (or any of its nested member groups).
    :param ldap_args: LdapSettings object
    :param user_account: User account name (sAMAccountName)
    :param group_dn: DN of the group (e.g. CN=ACL_SMS_gateway,OU=Groups,DC=example,DC=com)
    :return: True if user is a member of the group, False otherwise
    """
    l = ldap.initialize(ldap_args.server)
    l.protocol_version = ldap.VERSION3
    l.simple_bind_s(ldap_args.bind_user, ldap_args.bind_password)

    # Remove domain from user account if present (not present in sAMAccountName)
    if '@' in user_account:
        user_account = user_account.split('@')[0]

    ldap_filter = '(&(sAMAccountName={})(memberOf:1.2.840.113556.1.4.1941:={}))'.format(
        ldap.filter.escape_filter_chars(user_account), group_dn)
    ldap_args.log.debug('LDAP testing auth group: ' + ldap_filter)

    attrs = ['sAMAccountName']
    ldap_result_id = l.search(ldap_args.base, ldap.SCOPE_SUBTREE, ldap_filter, attrs)
    result_type, result_data = l.result(ldap_result_id, 0)
    ldap_args.log.debug('LDAP auth group test results (empty=auth failed): ' + str(result_data))

    if not result_data or result_type != ldap.RES_SEARCH_ENTRY:
        return False

    l.unbind_s()
    return True
