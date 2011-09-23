import mock
import unittest

from utils import get_signed_fb_request, get_access_tokens_from_signed_fb_request, fb_mock_cookie


class FBTestSuite(unittest.TestCase):

    @mock.patch("utils.get_access_token_from_code")
    def test_get_signed_fb_request_non_expired_key(self, mock):

        mock.return_value = "15996268430383|c58b2c04d1fef1554b6408dd-1474622354|as2tU6y_eTkbeMXJuCWVZ4P1ewM."

        data = get_access_tokens_from_signed_fb_request({'code': 'BLA', 'user_id': '1474622354'})
        self.assertTrue(data.get('access_token'), 'Should have an access token')
        self.assertTrue(data.get('session_key'), 'Should have a session key')
        self.assertEqual(data['expires'], "0", "Should not be expirig")

    @mock.patch("utils.get_access_token_from_code")
    def test_get_signed_fb_request_expired_key(self, mock):

        mock.return_value = "115996268430383|2.M6Q5rZjJIkfAO_0UNuIDSQ__.3600.1273741200-1474622354|z79TisIrBPIVKlm7i6qFGATy5Fg."

        data = get_access_tokens_from_signed_fb_request({'code': 'BLA', 'user_id': '1474622354'})
        self.assertTrue(data.get('access_token'), 'Should have an access token')
        self.assertTrue(data.get('session_key'), 'Should have a session key')
        self.assertNotEqual(data['expires'], "0", "Should be expiring")

    def test_create_mock_cookie(self):
        from django.conf import settings
        settings.FACEBOOK_API_KEY = "1234"
        settings.FACEBOOK_APP_ID = "5678"
        settings.FACEBOOK_SECRET_KEY = "mysecret"

        (cookie_name, cookie_secret) = fb_mock_cookie('123')
        response = get_signed_fb_request({cookie_name: cookie_secret},
                                         settings.FACEBOOK_APP_ID,
                                         settings.FACEBOOK_SECRET_KEY)
        self.assertTrue(response.get('issued_at'), 'Should have seen an issued_at')
        self.assertEqual(response.get('user_id'), '123', 'User ID does not match')

if __name__ == "__main__":
    unittest.main()
