from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect

from oauth2_facebook import get_signed_fb_request, decode_cookie_string

import logging


def fb_login(request):
    data = get_signed_fb_request(request.COOKIES)

    return HttpResponse("user returned: %s" % data['user_id'])


def logout(request):

    response = HttpResponseRedirect("/")

    # Force expiration of fbs_ cookies so that they are not being used.
    fbs_cookie_name = 'fbs_' + settings.FACEBOOK_API_KEY

    fbs_cookie = request.COOKIES.get(fbs_cookie_name)

    # If we are using the JavaScript OAuth library cookie, then we'll be unable to
    # logout because Facebook's Connect library is keyed to using the apiKey set
    # during FB.init.  Thus, you are unable to use it to delete the fbs_ cookie
    # without special JavaScript code that uses their routines, which gets
    # annoying if we have so many places in our code base to add it.
    #
    # A better way is just set it on Django's end, which will send an instruciton
    # to a set cookie on the first day of GMT (1970), which the browser will
    # realize is a delete cookie command.

    # If you don't get the domain= parameter right, you won't delete it.

    if fbs_cookie:
        logging.debug("User was using fbs_ cookie %s...forcing to delete." % fbs_cookie)
        cookie_dict = decode_cookie_string(fbs_cookie)

        base_domain = cookie_dict.get('base_domain')
        logging.debug("cookie_dict: %s" % (base_domain))

        # You can't delete cookies properly without the base_domain set.
        if base_domain:
            response.delete_cookie(fbs_cookie_name, domain="." + base_domain)

    return response
