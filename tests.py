import mock

import unittest
from oauth2_facebook import get_access_tokens_from_signed_fb_request


class FBTestSuite(unittest.TestCase):

    @mock.patch("oauth2_facebook.get_access_token_from_code")
    def test_get_signed_fb_request_non_expired_key(self, mock):

        mock.return_value = "15996268430383|c58b2c04d1fef1554b6408dd-1474622354|as2tU6y_eTkbeMXJuCWVZ4P1ewM."

        data = get_access_tokens_from_signed_fb_request({'code': 'BLA', 'user_id': '1474622354'})
        self.assertTrue(data.get('access_token'), 'Should have an access token')
        self.assertTrue(data.get('session_key'), 'Should have a session key')
        self.assertEqual(data['expires'], "0", "Should not be expirig")

    @mock.patch("oauth2_facebook.get_access_token_from_code")
    def test_get_signed_fb_request_expired_key(self, mock):

        mock.return_value = "115996268430383|2.M6Q5rZjJIkfAO_0UNuIDSQ__.3600.1273741200-1474622354|z79TisIrBPIVKlm7i6qFGATy5Fg."

        data = get_access_tokens_from_signed_fb_request({'code': 'BLA', 'user_id': '1474622354'})
        self.assertTrue(data.get('access_token'), 'Should have an access token')
        self.assertTrue(data.get('session_key'), 'Should have a session key')
        self.assertNotEqual(data['expires'], "0", "Should be expiring")

if __name__ == "__main__":
    unittest.main()
