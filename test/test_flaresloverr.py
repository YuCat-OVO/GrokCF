import unittest
from unittest.mock import patch, MagicMock
from contextlib import contextmanager
from urllib.parse import urlparse
import requests
from update_cookie import Flaresolverr, SessionCreationError, config


class TestSolverSession(unittest.TestCase):
    """Flaresolverr 会话管理器的单元测试"""

    @contextmanager
    def _mock_response(self, status_code=200, json_data=None):
        """创建模拟响应对象的上下文管理器"""
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.json.return_value = json_data or {}
        yield mock_resp

    def test_session_creation_success(self):
        """测试成功创建会话场景"""
        test_session_id = "test_session_123"
        mock_json = {"status": "ok", "solution": {"session": test_session_id}}

        with patch("requests.post") as mock_post:
            mock_post.return_value = self._mock_response(json_data=mock_json).gen
            with Flaresolverr.SolverSession() as session:
                self.assertEqual(session.session_id, test_session_id)
                mock_post.assert_called_once_with(
                    config.solver_url, json={"cmd": "sessions.create"}, timeout=60
                )

    def test_session_creation_failure(self):
        """测试服务器返回错误状态码时的异常处理"""
        error_message = "Invalid API key"
        mock_json = {"status": "error", "message": error_message}

        with patch("requests.post") as mock_post:
            mock_post.return_value = self._mock_response(json_data=mock_json).gen
            with self.assertRaises(SessionCreationError) as cm:
                with Flaresolverr.SolverSession():
                    pass

            self.assertIn(error_message, str(cm.exception))

    def test_network_failure_handling(self):
        """测试网络请求失败时的异常处理"""
        with patch("requests.post") as mock_post:
            mock_post.side_effect = requests.exceptions.ConnectionError("DNS failure")
            with self.assertRaises(SessionCreationError) as cm:
                with Flaresolverr.SolverSession():
                    pass

            self.assertIn("DNS failure", str(cm.exception))

    def test_proxy_config_parsing(self):
        """测试不同代理配置的解析逻辑"""
        test_cases = [
            (
                "socks5://user:pass@127.0.0.1:1080",
                {
                    "url": "socks5://127.0.0.1:1080",
                    "username": "user",
                    "password": "pass",
                },
            ),
            ("http://proxy.example.com", {"url": "http://proxy.example.com"}),
        ]

        for proxy_url, expected in test_cases:
            with self.subTest(proxy_url=proxy_url):
                session = Flaresolverr.SolverSession(proxy=proxy_url)
                result = session._create_proxy_config()
                self.assertEqual(result, expected)

    def test_invalid_proxy_handling(self):
        """测试无效代理URL的异常抛出"""
        invalid_proxies = ["invalid_url", "http://", "://missing_scheme.com"]

        for proxy in invalid_proxies:
            with self.subTest(proxy=proxy):
                session = Flaresolverr.SolverSession(proxy=proxy)
                with self.assertRaises(ValueError):
                    session._create_proxy_config()

    @patch("requests.post")
    @patch("logging.error")
    def test_session_cleanup_on_exit(self, mock_logging, mock_post):
        """测试上下文退出时会话销毁逻辑"""
        test_session_id = "cleanup_test_456"
        mock_json = {"status": "ok", "solution": {"session": test_session_id}}

        # 模拟创建成功
        mock_post.return_value = self._mock_response(json_data=mock_json).gen

        with Flaresolverr.SolverSession() as session:
            session.session_id = test_session_id  # 强制设置测试ID

        # 验证销毁请求参数
        expected_destroy_call = {"cmd": "sessions.destroy", "session": test_session_id}
        mock_post.assert_called_with(
            config.solver_url, json=expected_destroy_call, timeout=60
        )

    @patch("requests.post")
    def test_timeout_propagation(self, mock_post):
        """测试超时参数的正确传递"""
        test_timeout = 30
        mock_json = {"status": "ok", "solution": {"session": "timeout_test"}}

        with Flaresolverr.SolverSession(timeout=test_timeout) as session:
            mock_post.assert_called_once_with(
                config.solver_url, json={"cmd": "sessions.create"}, timeout=test_timeout
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
