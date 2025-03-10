import json
from unittest import TestCase, mock

import requests

from update_cookie import Byparr


class TestByparr(TestCase):
    def setUp(self):
        self.solver = Byparr()

    @mock.patch("requests.post")
    def test_success_flow(self, mock_post):
        """测试正常请求流程"""
        mock_response = mock.Mock()
        mock_response.json.return_value = {
            "status": "ok",
            "solution": {"cookies": [{"name": "clearance", "value": "test123"}]},
        }
        mock_post.return_value = mock_response

        result = self.solver.get_clearance_cookie()
        self.assertEqual(result, "test123")

    @mock.patch("requests.post")
    def test_network_failure(self, mock_post):
        """测试网络异常处理"""
        mock_post.side_effect = requests.ConnectionError("DNS failure")

        result = self.solver.get_clearance_cookie()
        self.assertEqual(result, "")

    @mock.patch("requests.post")
    def test_invalid_json_response(self, mock_post):
        """测试无效JSON响应处理"""
        mock_response = mock.Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.side_effect = json.JSONDecodeError("", "", 0)
        mock_response.text = "{invalid: json}"
        mock_post.return_value = mock_response

        result = self.solver.get_clearance_cookie()
        self.assertEqual(result, "")
