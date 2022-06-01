import os
from typing import List, Dict

import ldap, ldap.filter
from cachetools import cached, TTLCache
from logging import Logger


class LdapSettings:
    server: str
    base: str
    bind_user: str
    bind_password: str
    auth_sender_group_dn: str
    auth_viewer_group_dn: str
    default_domain: str
    also_list_missing_numbers: bool
    log: Logger


def get_ldap_args_from_env(log) -> LdapSettings:
    """
    Get LDAP settings from environment variables.
    :param log: Logger object
    :return: LdapSettings object
    """
    missing_envs = []

    def env(name: str) -> str:
        nonlocal missing_envs
        v = os.environ.get(name)
        if not v:
            missing_envs.append(name)
        return v or ''

    conf = LdapSettings()
    conf.server = env('LDAP_SERVER')
    conf.base = env('LDAP_BASE')
    conf.bind_user = env('LDAP_BIND_USER')
    conf.bind_password = env('LDAP_BIND_PASS')
    conf.auth_sender_group_dn = env('LDAP_AUTH_SENDER_GROUP')
    conf.auth_viewer_group_dn = env('LDAP_AUTH_VIEWER_GROUP')
    conf.default_domain = env('LDAP_AUTH_DEFAULT_DOMAIN')
    conf.also_list_missing_numbers = (env('LDAP_ALSO_LIST_MISSING_NUMBERS') .strip().lower() == 'true')
    conf.log = log

    if missing_envs:
        raise Exception('Missing environment variables: ' + ', '.join(missing_envs))

    return conf


def test_ldap_user_password(ldap_args: LdapSettings, user_account: str, password: str) -> bool:
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


@cached(cache=TTLCache(maxsize=1024, ttl=15))
def list_users_with_phone_num(ldap_args: LdapSettings) -> List[Dict]:
    """
    Returns a list of users with a mobile number set in their AD account.
    If LDAP_ALSO_LIST_MISSING_NUMBERS is true, returns everyone, but an
    empty string for those who have no number.
    :param ldap_args: LdapSettings object
    :return: list of accounts, their GUIDs and mobile numbers
    """
    l = ldap.initialize(ldap_args.server)
    l.protocol_version = ldap.VERSION3
    l.simple_bind_s(ldap_args.bind_user, ldap_args.bind_password)

    # Search for users with a mobile phone number
    ldap_filter = '(&(objectClass=person)(mobile=*))'
    if ldap_args.also_list_missing_numbers:
        ldap_filter = '(objectClass=person)'

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
    return [{
        'user': x[0][1]['sAMAccountName'][0].decode('utf-8'),
        'mobile': (x[0][1]['mobile'][0].decode('utf-8') if 'mobile' in x[0][1] else ''),
        'guid': x[0][1]['objectGUID'][0].hex()
    } for x in result_set]


def ldap_fetch_user_mobile(ldap_args: LdapSettings, user_guid: str) -> str:
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


def ldap_test_user_group_membership(ldap_args: LdapSettings, user_account: str, group_dn: str) -> bool:
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
