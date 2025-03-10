import json
import logging
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable
from contextlib import contextmanager
from time import monotonic
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
    :param interval: 刷新 Cookies 间隔秒数
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
        default=200000,
        gt=0,
        description="解析器请求超时时间（毫秒），最小值1",
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
        description="刷新 Cookies 间隔秒数（秒），最小值1",
    )
    min_exec_interval: int | None = Field(
        default=10,
        gt=0,
        description="最小的执行间隔秒数（秒），最小值1",
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
                config.solver_url,
                json=request_json,
                timeout=config.solver_timeout // 1000,
            )
            response.raise_for_status()
        except requests.RequestException as e:
            logging.error("请求失败: %s", str(e))
            return None
        try:
            response = response.json()
        except json.JSONDecodeError:
            logging.error("无效的JSON响应: %s", response.text)
            return None
        return response

    @staticmethod
    def _parse_cookies(response: dict[str, Any] | None) -> str:
        """从响应数据中提取cf_clearance cookie

        :param response: 解析器返回的响应字典
        :return: 找到的cookie值或空字符串
        """
        if not response:
            logging.warning("解析器响应为空")
            return ""
        if response.get("status") != "ok":
            logging.warning("异常响应状态: %s", response.get("status"))
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
    """通过 Flaresolverr 获取云防火墙凭证"""

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
                config.solver_url, json=create_json, timeout=self.timeout // 1000
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
                logging.error("会话销毁异常: %s", str(e))

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
            logging.error("会话销毁失败: %s", str(e))

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
    """通过 Byparr 获取云防火墙凭证

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


class TaskScheduler:
    """定时任务调度器，支持防止重复执行

    :param interval: 任务执行间隔时间（秒）
    :param task: 要执行的任务函数（无参数）
    :param min_interval: 最小执行间隔保护（默认10秒）
    """

    def __init__(
        self, interval: float, task: Callable[[], None], min_interval: float = 10
    ) -> None:
        if interval < min_interval:
            raise ValueError(f"间隔时间不能小于 {min_interval} 秒")

        self.interval = interval
        self.task = task
        self.min_interval = min_interval
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._last_run = 0.0
        self._thread = threading.Thread(target=self._run)

    def start(self) -> None:
        """启动任务调度器"""
        if self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread.start()

    def stop(self) -> None:
        """停止任务调度器"""
        self._stop_event.set()
        self._thread.join()

    def _run(self) -> None:
        """调度器主循环"""
        while not self._stop_event.is_set():
            elapsed = monotonic() - self._last_run
            if elapsed < self.interval:
                sleep_time = min(self.interval - elapsed, self.min_interval)
                self._stop_event.wait(sleep_time)
                continue

            if self._lock.acquire(blocking=False):
                try:
                    self.task()
                    self._last_run = monotonic()
                finally:
                    self._lock.release()
            else:
                self._stop_event.wait(self.min_interval)

    def trigger_now(self) -> bool:
        """立即触发任务执行（如果当前未运行）

        :return: 是否成功触发执行
        """
        if self._lock.acquire(blocking=False):
            try:
                self.task()
                self._last_run = monotonic()
                return True
            finally:
                self._lock.release()
        return False


def update_cookie(solver: Solver) -> None:
    """更新云防火墙的验证 Cookie。
    通过解析器获取最新云防火墙验证信息并更新到目标网站
    :param solver: 提供清除 Cookie 功能的解析器实例
    """
    if not (cookie := solver.get_clearance_cookie()):
        logging.error("获取验证信息失败: cookie 为空 (可能IP未被限制或解析器异常)")
        return
    logging.debug("获取到有效 Cookie: %s", cookie)
    endpoint = config.update_endpoint
    headers = {"Authorization": f"Bearer {config.endpoint_auth}"}
    payload = {"cf_clearance": f"cf_clearance={cookie}"}
    timeout = config.solver_timeout // 1000
    try:
        response = requests.post(
            url=endpoint,
            headers=headers,
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        logging.error("更新请求失败: %s", exc, exc_info=exc)
        return
    logging.info("Cookie 更新成功")


def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.info("开始运行")

    solver = Flaresolverr() if config.solver_type == "flaresolverr" else Byparr()

    tasker = TaskScheduler(
        config.interval, lambda: update_cookie(solver), config.min_exec_interval
    )
    tasker.start()


if __name__ == "__main__":
    main()
