import os
import time
import ldap


class LdapSettings:
    def __init__(self, server, base, bind_user, bind_password):
        self.server = server
        self.base = base
        self.bind_user = bind_user
        self.bind_password = bind_password


def get_ldap_args_from_env():
    ldap_server = os.environ.get('LDAP_SERVER')
    ldap_base = os.environ.get('LDAP_BASE')
    ldap_bind_user = os.environ.get('LDAP_BIND_USER')
    ldap_bind_password = os.environ.get('LDAP_BIND_PASS')

    if None in [ldap_server, ldap_base, ldap_bind_user, ldap_bind_password]:
        missing_envs = []
        if not ldap_server:
            misisng_envs.append('LDAP_SERVER')
        if not ldap_base:
            misisng_envs.append('LDAP_BASE')
        if not ldap_bind_user:
            missing_envs.append('LDAP_BIND_USER')
        if not ldap_bind_password:
            missing_envs.append('LDAP_BIND_PASS')

        err = 'Missing environment variables: {}'.format(', '.join(missing_envs))
        raise Exception(err)

    return LdapSettings(ldap_server, ldap_base, ldap_bind_user, ldap_bind_password)



last_ldap_query_time = 0
last_ldap_query_result = None
ldap_cache_ttl = 15


def list_users_with_phone_num(ldap_args: LdapSettings):
    # Return cached result if it's not too old
    global last_ldap_query_time
    global last_ldap_query_result
    if time.time() - last_ldap_query_time < ldap_cache_ttl:
        print('using cached LDAP result from {}'.format(last_ldap_query_time))
        return last_ldap_query_result

    # Connect
    l = ldap.initialize(ldap_args.server)
    l.protocol_version = ldap.VERSION3
    l.simple_bind_s(ldap_args.bind_user, ldap_args.bind_password)

    # Search for users with a mobile phone number
    ldap_filter = '(&(objectClass=person)(mobile=*))'
    attrs = ['cn', 'mobile', 'sAMAccountName', 'sn', 'objectGUID']
    ldap_result_id = l.search(ldap_args.base, ldap.SCOPE_SUBTREE, ldap_filter, attrs)
    result_set = []
    while 1:
        result_type, result_data = l.result(ldap_result_id, 0)
        if not result_data:
            break
        else:
            if result_type == ldap.RES_SEARCH_ENTRY:
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
    all_users = list_users_with_phone_num(ldap_args)
    for user in all_users:
        if user['guid'] == user_guid:
            return user['mobile']
    raise Exception('User not found')
