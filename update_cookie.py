import json
import logging
from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Any
from urllib.parse import urlparse

import requests
import validators
from pydantic import Field, HttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Config(BaseSettings):
    """应用程序运行时配置模型

    封装服务地址、监控目标和凭证更新等核心参数，提供类型安全的配置验证。
    :param solver_url: Flaresolverr 服务地址，自动添加 /v1 后缀
    :param solver_type: 解析器类型 (支持 flaresolverr/byparr，不区分大小写)
    :param target_url: 目标监控网站地址
    :param solver_timeout: 解析器请求超时时间（秒），最小值1
    :param update_endpoint: 云防火墙凭证更新端点 URL
    :param endpoint_auth: 端点认证密钥，至少6个字符
    :param interval: 健康检查间隔秒数，None 表示禁用
    :param proxy: 代理配置，格式：protocol://user:pass@host:port
    :param mihomo_url: Mihomo 服务地址
    :param mihomo_group_name: Mihomo 代理组名，至少2个字符

    :raises ValidationError: 当任何字段验证失败时抛出
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
        description="端点认证信息",
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
    """Solver 会话创建失败时抛出的异常"""


class Solver(ABC):
    @abstractmethod
    def get_clearance_cookie(self) -> str:
        """获取云防火墙验证凭证

        通过解析器服务获取并返回最新的cf_clearance cookie值
        """

    @staticmethod
    def _request_solver(request_json: dict[str, Any]) -> dict[str, Any] | None:
        """执行解析器请求并返回响应数据

        :param request_json: 请求负载的JSON字典
        :return: 成功返回响应字典，失败返回None
        """

        try:
            response = requests.post(
                config.solver_url, json=request_json, timeout=config.solver_timeout
            )
            response.raise_for_status()
        except requests.RequestException as e:
            logging.error(f"请求失败: {str(e)}")
            return None
        try:
            response = response.json()
        except json.JSONDecodeError:
            logging.error(f"无效的JSON响应: {response.text}")
            return None
        return response

    @staticmethod
    def _parse_cookies(response: dict[str, Any] | None) -> str:
        """从响应数据中提取cf_clearance cookie

        :param response: 解析器返回的响应字典
        :return: 找到的cookie值或空字符串
        """
        if not response or response.get("status") != "ok":
            logging.warning(f"异常响应状态: {response.get('status')}")
            return ""
        return next(
            (
                c.get("value", "")
                for c in response.get("solution", {}).get("cookies", [])
                if c.get("name") == "cf_clearance"
            ),
            "",
        )


class Flaresolverr(Solver):
    class SolverSession:
        """管理Flaresolverr会话生命周期"""

        def __init__(self, proxy: str | None) -> None:
            if not proxy:
                self.proxy = proxy
            self.session_id: str | None = None
            self.timeout: int = config.solver_timeout

        def __enter__(self) -> "Flaresolverr.SolverSession":
            """创建并返回激活的会话实例"""
            create_json = {"cmd": "sessions.create"}
            if proxy_config := self._create_proxy_config():
                create_json["proxy"] = proxy_config

            response = requests.post(
                config.solver_url, json=create_json, timeout=self.timeout
            ).json()

            if response.get("status") == "ok":
                self.session_id = response["solution"]["session"]
                return self
            raise SessionCreationError(f"会话创建失败: {response.get('message')}")

        def __exit__(self, *exc_info: Any) -> None:
            """确保会话资源释放"""
            if self.session_id:
                self._destroy_session()

        def _create_proxy_config(self) -> dict[str, str] | None:
            """构造代理配置字典
            由于 Session 是为了解决 Flaresolverr get 方法无法使用带有用户名以及密码的情况的
            因此返回的代理配置中目前一定需要用户名和密码
            """
            if not self.proxy:
                return None

            parsed = urlparse(self.proxy)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"无效代理URL格式: {self.proxy}")

            return {
                "url": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}",
                "username": parsed.username,
                "password": parsed.password,
            }

        def _destroy_session(self) -> None:
            """内部会话销毁方法"""
            try:
                requests.post(
                    config.solver_url,
                    json={"cmd": "sessions.destroy", "session": self.session_id},
                    timeout=self.timeout,
                ).raise_for_status()
            except requests.RequestException as e:
                logging.error(
                    f"会话销毁异常: {str(e)}",
                )

    @contextmanager
    def _managed_session(self) -> "SolverSession":
        """上下文管理器创建代理会话"""
        session = self.SolverSession(proxy=config.proxy)
        try:
            yield session
        finally:
            if session.session_id:
                self._destroy_session(session.session_id)

    @staticmethod
    def _destroy_session(session_id: str) -> None:
        """销毁指定会话"""
        destroy_json = {"cmd": "sessions.destroy", "session": session_id}
        try:
            requests.post(
                config.solver_url, json=destroy_json, timeout=config.solver_timeout
            ).raise_for_status()
        except requests.RequestException as e:
            logging.error(
                f"会话销毁失败: {str(e)}",
            )

    def get_clearance_cookie(self) -> str:
        """通过Flaresolverr获取云防火墙验证cookie"""
        request_json = {
            "cmd": "request.get",
            "url": config.target_url,
            "maxTimeout": config.solver_timeout,
        }
        if config.proxy:
            return self._handle_proxy_request(request_json)
        return self._handle_direct_request(request_json)

    def _handle_proxy_request(self, request_json: dict) -> str:
        """处理带代理的请求"""
        parsed = urlparse(config.proxy)
        use_session = any([parsed.username, parsed.password])
        if use_session:
            with self._managed_session() as session:
                request_json["session"] = session.session_id
                return self._parse_cookies(self._request_solver(request_json))

        request_json["proxy"] = {"url": config.proxy}
        return self._parse_cookies(self._request_solver(request_json))

    def _handle_direct_request(self, request_json: dict) -> str:
        """处理直接请求"""
        return self._parse_cookies(self._request_solver(request_json))


class Byparr(Solver):
    """通过外部解析服务获取云防火墙凭证

    注意：当前实现可能返回空Cookie，暂时优先使用 Flaresolverr
    """

    def get_clearance_cookie(self) -> str:
        """获取云防火墙的验证 Cookie
        通过调用远程解析服务获取最新验证信息
        :return: clearance cookie 值，获取失败时返回空字符串
        """
        request_json = {
            "cmd": "request.get",
            "url": config.target_url,
            "maxTimeout": config.solver_timeout,
        }
        if config.proxy:
            logging.error("Byparr 不支持代理设置，请前往其环境中设置代理")
        response = self._request_solver(request_json)
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
            timeout=config.solver_timeout,
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
