from django.conf.urls.defaults import patterns

from oauth2_facebook.views import fb_login, fb_logout

urlpatterns = patterns('',
    (r'fb_login/', fb_login),
    (r'fb_logout/', fb_logout
