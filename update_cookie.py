import json
import logging
from abc import ABC, abstractmethod
from urllib.parse import urlparse

import requests
import validators
from pydantic import Field, HttpUrl, field_validator
from pydantic_settings import BaseSettings


class SessionCreationError(RuntimeError):
    """自定义会话创建异常"""

    pass


class Config(BaseSettings):
    """整个应用程序的运行时配置
    包含服务地址、监控目标、凭证更新等核心参数配置，采用类型安全的验证机制。
    :param solver_url: Flaresolverr 服务地址
    :param solver_type: 解析器类型(Flaresolverr/Byparr)
    :param target_url: 目标监控网站地址
    :param update_endpoint: 云防火墙凭证更新端点
    :param interval: 健康检查间隔时间（秒），最小值1
    :param proxy: 可选代理配置，格式：protocol://user:pass@host:port
    """

    solver_url: str = Field(
        default="http://localhost:8191",
        description="Flaresolverr 服务地址",
    )
    solver_type: str = Field(
        default="flaresolverr",
        description="解析器类型(Flaresolverr/Byparr)",
        pattern="^(?i)(flaresolverr|byparr)$",
    )
    target_url: str = Field(
        default="https://grok.com",
        description="目标监控网站地址",
    )
    update_endpoint: str = Field(
        default="http://localhost:8000/set/cf_clearance",
        description="云防火墙凭证更新端点",
    )
    interval: int | None = Field(
        default=300,
        gt=0,
        description="健康检查间隔时间（秒），最小值1",
    )
    proxy: str | None = Field(
        default=None,
        description="可选代理配置，格式：protocol://user:pass@host:port",
    )
    mihomo_url: HttpUrl | None = Field(
        default="http://localhost:8000",
        description="Mihomo服务地址",
    )
    mihomo_group_name: str | None = Field(
        default="XAI",
        description="Mihomo 中代理的组名",
    )

    @field_validator("solver_url")
    def check_solver_url(cls, value):
        parsed_url = urlparse(value)
        if parsed_url.scheme not in ["http", "https"]:
            raise ValueError("Invalid proxy protocol")
        if not validators.url(value, simple_host=True):
            raise ValueError("Invalid URL format")
        return value.rstrip("/") + "/v1"

    @field_validator("target_url")
    def check_target_url(cls, value):
        parsed_url = urlparse(value)
        if parsed_url.scheme not in ["http", "https"]:
            raise ValueError("Invalid proxy protocol")
        if not validators.url(value, simple_host=True):
            raise ValueError("Invalid URL format")
        return value

    @field_validator("update_endpoint")
    def check_update_endpoint(cls, value):
        if not validators.url(value, simple_host=True):
            raise ValueError("Invalid URL format")
        return value

    @field_validator("proxy")
    def check_proxy(cls, value):
        if value:
            parsed_url = urlparse(value)
            if parsed_url.scheme not in ["http", "https", "socks5"]:
                raise ValueError("Invalid proxy protocol")
            netloc_split = parsed_url.netloc.split("@")
            if len(netloc_split) > 1:
                logging.debug("Proxy URL contains username and password")
                name_password = netloc_split[0].split(":")
                if (
                    len(name_password) <= 1
                    or not name_password[0]
                    or not name_password[1]
                ):
                    raise ValueError("Invalid username and password")
        return value


config = Config()


class Solver(ABC):
    @abstractmethod
    def get_clearance_cookie(self) -> str:
        """获取云防火墙凭证

        通过解析器获取并返回云防火墙的有效凭证

        :return: 凭证字符串
        """
        pass


class Flaresolverr(Solver):
    class SolverSession:
        """Flaresolverr 会话管理器，使用上下文管理器确保资源清理"""

        def __init__(self, proxy: str | None = None, timeout: int = 60) -> None:
            """初始化会话管理器

            :param proxy: 代理服务器 URL (支持 http/socks，格式: scheme://[user:pass@]host:port)
            :param timeout: 请求超时时间（秒）
            """
            self.timeout = timeout
            self.session_id = None
            self.proxy = proxy

        def _create_proxy_config(self) -> dict | None:
            """构造代理配置字典"""
            if not self.proxy:
                return None

            parsed = urlparse(self.proxy)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"无效代理 URL: {self.proxy}")

            # 提取认证信息
            config = {"url": f"{parsed.scheme}://{parsed.hostname}"}
            if parsed.port:
                config["url"] += f":{parsed.port}"

            if parsed.username or parsed.password:
                config.update(
                    {"username": parsed.username, "password": parsed.password}
                )
            return config

        def __enter__(self):
            """创建会话并返回当前实例"""
            create_json = {"cmd": "sessions.create"}

            if proxy_config := self._create_proxy_config():
                create_json["proxy"] = proxy_config

            try:
                response = requests.post(
                    config.solver_url, json=create_json, timeout=self.timeout
                )
                response.raise_for_status()
            except requests.RequestException as e:
                raise SessionCreationError(f"请求失败: {str(e)}") from e

            data = response.json()
            if data.get("status") == "ok":
                self.session_id = data["solution"]["session"]
                return self
            raise SessionCreationError(f"创建失败: {data.get('message', '未知错误')}")

        def __exit__(self, exc_type, exc_val, exc_tb) -> None:
            """销毁会话并处理异常"""
            if not self.session_id:
                return

            destroy_json = {"cmd": "sessions.destroy", "session": self.session_id}
            try:
                response = requests.post(
                    config.solver_url,
                    json=destroy_json,
                    timeout=self.timeout,
                )
                response.raise_for_status()
            except requests.RequestException as e:
                logging.error("会话销毁失败: %s", str(e))


class Byparr(Solver):
    """用于通过外部解析服务获取云防火墙凭证的求解器"""

    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def to_solver_json() -> dict[str, str]:
        """构建 Solver 请求参数

        :return: 包含命令和目标URL的字典
        """
        request_json = {"cmd": "request.get", "url": config.target_url}
        if config.proxy:
            logging.error("Byparr 不支持代理设置，请前往其环境中设置代理")
        return request_json

    def get_clearance_cookie(self) -> str:
        """获取云防火墙的验证 Cookie
        通过调用远程解析服务获取最新验证信息
        :return: clearance cookie 值，获取失败时返回空字符串
        """
        try:
            response = requests.post(config.update_endpoint, json=self.to_solver_json())
            response.raise_for_status()
        except requests.RequestException as e:
            logging.error(f"请求失败: {str(e)}")
            return ""

        try:
            request_data = response.json()
        except json.JSONDecodeError:
            logging.error(f"无效的JSON响应: {response.text[:200]}")
            return ""

        if request_data.get("status") != "ok":
            logging.warning(f"异常响应状态: {request_data.get('status')}")
            return ""

        cookies = request_data.get("solution", {}).get("cookies", [])
        return next(
            (c.get("value", "") for c in cookies if c.get("name") == "clearance"), ""
        )
