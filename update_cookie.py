import json
import logging
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urlparse

import requests
import validators
from pydantic import Field, HttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

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
    solver_timeout: int = Field(
        default=300,
        gt=0,
        description="解析器请求超时时间（秒），最小值1",
    )
    update_endpoint: str = Field(
        default="http://localhost:8000/set/cf_clearance",
        description="云防火墙凭证更新端点",
    )
    endpoint_auth: str = Field(
        default="sk-123456",
        description="端点认证信息，格式：username:password",
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


class SessionCreationError(RuntimeError):
    """自定义会话创建异常"""

    pass


class Solver(ABC):
    @abstractmethod
    def get_clearance_cookie(self) -> str:
        """获取云防火墙凭证

        通过解析器获取并返回云防火墙的有效凭证

        :return: 凭证字符串
        """
        pass

    @staticmethod
    def _request_solver(request_json: dict) -> dict[str, Any]:
        """请求解析器并返回响应数据

        :param request_json: 请求数据字典
        :return: 获取到的数据字典
        """
        try:
            response = requests.post(config.solver_url, json=request_json)
            response.raise_for_status()
        except requests.RequestException as e:
            logging.error(f"请求失败: {str(e)}")
            return {}

        try:
            response = response.json()
        except json.JSONDecodeError:
            logging.error(f"无效的JSON响应: {response.text[:200]}")
            return {}

        return response

    @staticmethod
    def _parse_cookies(response: dict) -> str:
        """解析响应数据中的 Cookie

        :param response: 响应数据字典
        :return: 获取的 cf_clearance cookie 值
        """
        if response.get("status") != "ok":
            logging.warning(f"异常响应状态: {response.get('status')}")
            return ""

        cookies = response.get("solution", {}).get("cookies", [])
        return next(
            (c.get("value", "") for c in cookies if c.get("name") == "cf_clearance"),
            "",
        )


class Flaresolverr(Solver):
    class SolverSession:
        """Flaresolverr 会话管理器，使用上下文管理器确保资源清理"""

        def __init__(self, proxy: str | None = None, timeout: int = 300) -> None:
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

    def get_clearance_cookie(self):
        request_json = {"cmd": "request.get", "url": config.target_url}
        if config.proxy:
            logging.debug(f"正在使用代理: {config.proxy}")
            split_proxy = config.proxy.split("@")
            if len(split_proxy) > 1:
                logging.debug("代理中含有用户名和密码,使用session创建器")
                with self.SolverSession(proxy=config.proxy) as session:
                    request_json["session"] = session.session_id
                    response = self._request_solver(request_json)
            else:
                logging.debug("代理中不含有用户名和密码,直接请求")
                request_json["proxy"] = {"url": config.proxy}
                response = self._request_solver(request_json)
                return self._parse_cookies(response)
        else:
            logging.debug("未使用代理")
            response = self._request_solver(request_json)
            return self._parse_cookies(response)


class Byparr(Solver):
    """用于通过外部解析服务获取云防火墙凭证的求解器
    这玩意貌似目前会返回空 Cookie
    """

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
        response = self._request_solver(self.to_solver_json())
        return self._parse_cookies(response)


def update_cookie(solver) -> None:
    """更新云防火墙的验证 Cookie

    通过调用解析器获取最新的云防火墙验证信息，并更新到目标网站

    :return: None
    """
    cookie = solver.get_clearance_cookie()
    if not cookie:
        logging.error(
            "获取验证信息失败,cookie为空,可能您的IP比较干净或者解析器出现问题"
        )
        return
    else:
        logging.debug(f"获取到的Cookie: {cookie}")
    request_header = {"Authorization": f"Bearer {config.endpoint_auth}"}
    try:
        # 修改cf_clearance POST /set/cf_clearance {cf_clearance: "cf_clearance=XXXXXXXX"} 更新cf_clearance Cookie
        response = requests.post(
            config.update_endpoint,
            headers=request_header,
            json={"cf_clearance": f"cf_clearance={cookie}"},
        )
        response.raise_for_status()
    except requests.RequestException as e:
        logging.error(f"更新失败: {str(e)}")
        return

    logging.info(f"更新成功, Cookie: {cookie}")


def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.info("开始运行")

    solver = Flaresolverr() if config.solver_type == "flaresolverr" else Byparr()
    update_cookie(solver)


if __name__ == "__main__":
    main()
