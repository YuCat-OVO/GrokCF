import unittest
from pydantic import ValidationError
from update_cookie import Config


class ConfigValidationTests(unittest.TestCase):
    """测试配置模型的验证逻辑和类型约束"""

    def test_default_values(self):
        """测试字段默认值是否符合预期"""
        config = Config()
        self.assertEqual(config.solver_url, "http://localhost:8191/v1")
        self.assertEqual(config.solver_type.lower(), "flaresolverr")
        self.assertEqual(str(config.target_url), "https://grok.com")
        self.assertEqual(config.interval, 300)

    def test_solver_url_processing(self):
        """测试solver_url后缀处理逻辑"""
        # 测试自动添加/v1后缀
        config = Config(solver_url="http://demo.com")
        self.assertEqual(config.solver_url, "http://demo.com/v1")

        # 测试已有斜杠的处理
        config = Config(solver_url="http://demo.com/")
        self.assertEqual(config.solver_url, "http://demo.com/v1")

    def test_solver_url_validation(self):
        """测试solver_url格式验证"""
        # 有效URL
        valid_urls = ["http://localhost:8080", "https://api.example.com/path"]
        for url in valid_urls:
            with self.subTest(url=url):
                config = Config(solver_url=url)
                self.assertTrue(config.solver_url.startswith(url))

        # 无效URL
        invalid_urls = ["not_a_url", "ftp://invalid.scheme", "http:///missing.host"]
        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    Config(solver_url=url)

    def test_solver_type_pattern(self):
        """测试解析器类型正则约束"""
        # 有效类型（大小写不敏感）
        valid_types = ["Flaresolverr", "BYparr", "flaresolverr"]
        for t in valid_types:
            with self.subTest(type=t):
                config = Config(solver_type=t)
                self.assertTrue(
                    config.solver_type.lower() in {"flaresolverr", "byparr"}
                )

        # 无效类型
        with self.assertRaises(ValidationError):
            Config(solver_type="invalid_solver")

    def test_interval_constraints(self):
        """测试间隔时间的数值约束"""
        # 有效值
        Config(interval=1)
        Config(interval=300)

        # 边界值测试
        with self.assertRaises(ValidationError):
            Config(interval=0)

        with self.assertRaises(ValidationError):
            Config(interval=-5)

    def test_proxy_validation(self):
        """测试代理URL格式验证"""
        # 有效代理配置
        valid_proxies = ["http://user:pass@proxy.com:8080", "socks5://localhost:1080"]
        for proxy in valid_proxies:
            with self.subTest(proxy=proxy):
                config = Config(proxy=proxy)
                self.assertEqual(config.proxy, proxy)

        # 无效配置
        invalid_proxies = [
            "missing.protocol",
            "http://:password@host",  # 缺少用户名
        ]
        for proxy in invalid_proxies:
            with self.subTest(proxy=proxy):
                with self.assertRaises(ValueError):
                    Config(proxy=proxy)


if __name__ == "__main__":
    unittest.main()
