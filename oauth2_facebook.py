from django.conf import settings

import base64
import hashlib
import hmac
import json
import logging
import re
import urllib
import urllib2

BASE_LINK = "https://graph.facebook.com"


def base64_urldecode(data):
    # 1. Pad the encoded string with "+".  See
    # http://fi.am/entry/urlsafe-base64-encodingdecoding-in-two-lines/
    data += "=" * (4 - (len(data) % 4) % 4)

    return base64.urlsafe_b64decode(data)


def parse_signed_request(signed_request, secret):
    """ When a user authenticates via the JavaScript SDK, an fbsr_ cookie() gets
    set that can be used to validate the uid.  The payload includes an
    authorization code that requires an extra network request to Facebook to
    retrieve the session key/access token."""

    encoded_sig, payload = signed_request.split('.', 2)

    sig = base64_urldecode(encoded_sig)
    data = json.loads(base64_urldecode(payload))

    if data.get('algorithm').upper() != 'HMAC-SHA256':
        return None
    else:
        expected_sig = hmac.new(secret, msg=payload, digestmod=hashlib.sha256).digest()

    if sig != expected_sig:
        return None

    return data

def get_app_token_helper(data=None):
    if not data:
        data = {}

    try:
        token_request = urllib.urlencode(data)

        app_token = urllib2.urlopen(BASE_LINK + "/oauth/access_token?%s" % token_request).read()
    except urllib2.HTTPError, e:
        logging.debug("Exception trying to grab Facebook App token (%s)" % e)
        return None

    matches = re.match(r"access_token=(?P.*)", app_token).groupdict()

    return matches.get('token')


def get_access_token_from_code(code, redirect_url=None):
    """ OAuth2 code to retrieve an application access token. """

    data = {
        'client_id': settings.FACEBOOK_APP_ID,
        'client_secret': settings.FACEBOOK_SECRET_KEY,
        'code': code
        }

    if redirect_url:
        data['redirect_uri'] = redirect_url
    else:
        data['redirect_uri'] = ''

    return get_app_token_helper(data)


def get_signed_fb_request(cookies, app_id, app_secret, fetch_tokens=False):
    """Backwards compatibility routine to create a cookie_response dictionary
    that can be used throughout our app."""

    cookie = cookies.get("fbsr_" + app_id, "")

    if not cookie:
        return None

    data = parse_signed_request(signed_request=cookie, secret=app_secret)

    # We explictly do not try to grab the user's access token unless we absolutely need to do so,
    # since Facebook OAuth2 requires a separate server-side request to fetch that data.
    if fetch_tokens:
        logging.debug("fetching tokens in get_signed_fb_request")
        data = get_access_tokens_from_signed_fb_request(data)
    else:
        # Use so that backwards compatible Python OAuth v1.0 that used get_user_from_cookie()
        # to still use user_id.
        if data and data.get('user_id'):
            data['uid'] = data['user_id']
        else:
            raise Exception("Something unexpected happen with the signed request %s...no user_id got passed in?" % data)

    return data


def get_access_tokens_from_signed_fb_request(data):
    if data:
        response = get_access_token_from_code(data.get('code', ''))

        if response:
            token_response = {}
            (app_id, session_key, digest) = response.split('|')

            # http://www.quora.com/Do-the-OAuth2-access-tokens-in-the-new-Facebook-Graph-API-expire
            # expiring_session_key = "2." session_secret ".3600." expire_at "-" user_id
            # nonexpiring_session_key = session_secret "-" user_id

            non_expiring_session = re.match(r"^(?P<session_secret>.*?)\-(?P<user_id>.*?)$", session_key)
            expiring_session = re.match(r"^2\.(?P<session_secret>.*?)\.3600\.(?P<expire_time>.*?)-(?P<user_id>.*?)$", session_key)

            if expiring_session:
                token_response["expires"] = expiring_session.groupdict().get('expire_time')
                token_response["uid"] = expiring_session.groupdict().get('user_id')
            elif non_expiring_session:
                token_response["expires"] = "0"
                token_response["uid"] = non_expiring_session.groupdict().get('user_id')

            assert token_response['uid'] == data['user_id']  # sanity check that the cookie matches

            token_response['fbsr_signed'] = True   # for debugging purposes
            token_response['access_token'] = response
            token_response['session_key'] = session_key

            return token_response

    return None


def decode_cookie_string(cookie_string):
    # The decode_cookie_string is how Facebook's Connect Library pulls out
    # data within its fbs_ cookies.  They URL-encode the cookie value and then
    # store it as another nested set of key/value pairs.  One of them
    # is base_domain=, which we need to clear the cookie.  If you don't
    # have the domain= parameter set in the cookie, you can't clear the cookie.

    unquoted_cookie = urllib.unquote(cookie_string)

    # A much better way -- http://atomized.org/2008/06/parsing-url-query-parameters-in-python/
    try:
        cookie_dict = dict([part.split('=') for part in unquoted_cookie.split('&')])
    except ValueError:
        logging.debug("Bad cookie parsing of %s" % (unquoted_cookie))

    return cookie_dict


