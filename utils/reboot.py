import time
import json
import os
import sys
import paramiko

# 添加项目根目录到路径，以便导入utils模块
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from utils.connect import load_config, connect, disconnect, command_execute
from utils.logger import get_logger


class RebootManager:
    """
    麒麟系统重启管理工具
    通过SSH连接执行重启操作，并等待系统重启完成
    """

    def __init__(self, config_path="config/account.yaml", hostname=None):
        """
        初始化重启管理器

        Args:
            config_path: 配置文件路径
            hostname: 主机名（可选），如果指定则只操作该主机，否则需要后续调用时指定
        """
        self.config = load_config(config_path)
        if self.config is None:
            raise ValueError("加载配置文件失败或配置文件为空")
        if not isinstance(self.config, dict):
            raise ValueError(f"配置文件必须为字典, 实际类型为: {type(self.config)}")

        hosts_config = self.config.get("hosts", {})
        # 如果hosts是字符串格式的字典，需要解析
        if isinstance(hosts_config, str):
            try:
                self.hosts = json.loads(hosts_config)
            except json.JSONDecodeError:
                raise ValueError(f"无法解析hosts配置: {hosts_config}")
        else:
            self.hosts = hosts_config

        self.user = self.config.get("user")
        self.password = self.config.get("password")
        self.wait_time = self.config.get("wait_time", 30)  # 等待SSH服务启动的时间（秒）
        self.reboot_timeout = self.config.get("reboot_time", 1000)  # 重启超时时间（秒）

        if not isinstance(self.hosts, dict):
            raise ValueError(f"hosts配置必须为字典, 实际类型为: {type(self.hosts)}")
        if not self.hosts:
            raise ValueError("hosts配置不能为空")
        if not all([self.user, self.password]):
            missing = [
                k
                for k, v in {
                    "user": self.user,
                    "password": self.password,
                }.items()
                if not v
            ]
            raise ValueError(f"缺少必要的配置项: {missing}")

        self.logger = get_logger()
        self.ssh = None
        self.hostname = hostname
        self.host = None

        # 如果指定了hostname，则设置对应的host
        if hostname:
            self._set_host(hostname)

    def _set_host(self, hostname):
        """
        设置要操作的主机

        Args:
            hostname: 主机名（配置中的key）或IP地址
        """
        if hostname in self.hosts:
            self.hostname = hostname
            self.host = self.hosts[hostname]
        elif hostname in self.hosts.values():
            # 如果hostname是IP地址，找到对应的主机名
            for name, ip in self.hosts.items():
                if ip == hostname:
                    self.hostname = name
                    self.host = ip
                    break
        else:
            raise ValueError(
                f"主机 '{hostname}' 不在配置的hosts中: {list(self.hosts.keys())}"
            )

    def _wait_for_ssh(self, max_wait_time=None):
        """
        等待SSH服务可用

        Args:
            max_wait_time: 最大等待时间（秒），默认使用配置中的reboot_timeout

        Returns:
            bool: SSH服务是否可用
        """
        if max_wait_time is None:
            max_wait_time = self.reboot_timeout

        self.logger.info(
            f"{self.hostname}\t等待SSH服务启动，最多等待 {max_wait_time} 秒..."
        )
        start_time = time.time()
        check_interval = 1  # 每1秒检查一次
        last_log_time = 0  # 上次记录日志的时间

        # 导入必要的模块
        import paramiko
        import logging
        import sys
        import io

        # 配置paramiko日志，抑制详细错误输出
        paramiko_logger = logging.getLogger("paramiko")
        original_level = paramiko_logger.level
        paramiko_logger.setLevel(logging.CRITICAL)

        while time.time() - start_time < max_wait_time:
            old_stderr = None
            try:
                # 临时重定向stderr来抑制异常堆栈输出
                old_stderr = sys.stderr
                sys.stderr = io.StringIO()

                test_ssh = paramiko.SSHClient()
                test_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # 使用较短的超时时间（3秒）进行快速检查
                test_ssh.connect(
                    hostname=self.host,
                    username=self.user,
                    password=self.password,
                    timeout=3,
                    look_for_keys=False,
                    allow_agent=False,
                )
                test_ssh.close()

                # 恢复stderr
                if old_stderr:
                    sys.stderr = old_stderr

                elapsed_time = time.time() - start_time
                self.logger.info(
                    f"{self.hostname}\tSSH服务已启动，耗时 {elapsed_time:.2f} 秒"
                )
                return True
            except Exception:
                # 恢复stderr（抑制异常堆栈输出）
                if old_stderr:
                    sys.stderr = old_stderr

                elapsed_time = time.time() - start_time
                # 每10秒记录一次日志，避免日志过多
                if elapsed_time - last_log_time >= 10:
                    self.logger.info(
                        f"{self.hostname}\tSSH服务尚未就绪，已等待 {elapsed_time:.1f} 秒..."
                    )
                    last_log_time = elapsed_time
                time.sleep(check_interval)

        # 恢复paramiko日志级别
        paramiko_logger.setLevel(original_level)

        self.logger.error(
            f"{self.hostname}\t等待SSH服务超时，已等待 {max_wait_time} 秒"
        )
        return False

    def _get_system_info(self):
        """获取系统信息"""
        try:
            uname_result = command_execute(self.ssh, "uname -a")
            self.logger.info(f"{self.hostname}\t系统信息: {uname_result.strip()}")
        except Exception as e:
            self.logger.warning(f"{self.hostname}\t无法获取系统信息: {str(e)}")

    def _read_command_output(self, stdout, stderr):
        """读取命令输出"""
        try:
            stdout_output = stdout.read().decode("utf-8", errors="ignore")
            stderr_output = stderr.read().decode("utf-8", errors="ignore")
            if stdout_output:
                self.logger.debug(f"{self.hostname}\t重启命令输出: {stdout_output}")
            if stderr_output:
                self.logger.debug(f"{self.hostname}\t重启命令错误输出: {stderr_output}")
        except Exception:
            pass  # 连接可能已经断开，忽略错误

    def _check_user_permissions(self):
        """检查当前用户是否有重启权限"""
        try:
            # 检查当前用户是否为root
            whoami_result = command_execute(self.ssh, "whoami").strip()
            if whoami_result == "root":
                self.logger.info(f"{self.hostname}\t当前用户是root，无需sudo")
                return False  # 不需要sudo

            # 检查是否有sudo权限且无需密码
            try:
                stdin, stdout, stderr = self.ssh.exec_command(
                    "sudo -n reboot 2>&1", timeout=2
                )
                test_sudo = stdout.read().decode("utf-8", errors="ignore")
            except Exception:
                test_sudo = ""
            if (
                "password" not in test_sudo.lower()
                and "permission denied" not in test_sudo.lower()
            ):
                self.logger.info(f"{self.hostname}\t用户有sudo权限且无需密码")
                return True  # 需要sudo但无需密码

            return True  # 需要sudo且需要密码
        except Exception as e:
            self.logger.debug(f"{self.hostname}\t检查权限时出错: {str(e)}")
            return True  # 默认尝试使用sudo

    def _execute_reboot_command(self):
        """执行重启命令并确认执行状态"""
        self.logger.info(f"{self.hostname}\t正在执行重启命令...")

        # 检查是否需要sudo
        need_sudo = self._check_user_permissions()

        if need_sudo:
            # 使用sudo -S通过stdin传递密码
            command = "sudo -S reboot"
            self.logger.info(
                f"{self.hostname}\t使用sudo执行重启命令（将通过stdin传递密码）..."
            )
        else:
            # 直接使用reboot命令
            command = "reboot"
            self.logger.info(f"{self.hostname}\t直接执行重启命令（root用户）...")

        # 执行重启命令
        stdin, stdout, stderr = self.ssh.exec_command(command, timeout=5)

        # 如果需要sudo，通过stdin传递密码
        if need_sudo:
            try:
                stdin.write(f"{self.password}\n")
                stdin.flush()
                stdin.channel.shutdown_write()
            except Exception as e:
                self.logger.debug(
                    f"{self.hostname}\t写入密码时出错（可能命令已执行）: {str(e)}"
                )

        # 等待命令开始执行（reboot命令执行很快，连接会立即断开）
        exit_status = None
        stdout_output = ""
        stderr_output = ""

        try:
            # 尝试读取输出（可能为空，因为reboot会立即断开连接）
            stdout_output = stdout.read().decode("utf-8", errors="ignore").strip()
            stderr_output = stderr.read().decode("utf-8", errors="ignore").strip()

            # 等待命令状态（reboot通常不会返回，连接会断开）
            # 设置超时避免无限等待
            try:
                exit_status = stdout.channel.recv_exit_status()
            except Exception:
                # 对于reboot命令，连接断开是正常的，exit_status可能无法获取
                pass

        except Exception as e:
            # 连接断开是reboot命令的正常行为
            self.logger.debug(
                f"{self.hostname}\t读取命令输出时连接断开（这是正常的）: {str(e)}"
            )

        # 记录命令执行信息
        if stdout_output:
            self.logger.info(f"{self.hostname}\t重启命令输出: {stdout_output}")
        if stderr_output:
            if "permission denied" in stderr_output.lower() or "密码" in stderr_output:
                self.logger.error(
                    f"{self.hostname}\t重启命令执行失败（权限不足）: {stderr_output}"
                )
                raise Exception(f"重启命令执行失败: {stderr_output}")
            else:
                self.logger.warning(
                    f"{self.hostname}\t重启命令警告输出: {stderr_output}"
                )

        # 如果能够获取退出状态码，检查是否成功
        if exit_status is not None:
            if exit_status == 0:
                self.logger.info(
                    f"{self.hostname}\t重启命令执行成功（退出码: {exit_status}）"
                )
            else:
                self.logger.error(
                    f"{self.hostname}\t重启命令执行失败（退出码: {exit_status}）"
                )
                raise Exception(f"重启命令执行失败，退出码: {exit_status}")
        else:
            # 无法获取退出状态通常是正常的（reboot会断开连接）
            # 检查是否有错误输出
            if stderr_output and (
                "permission denied" in stderr_output.lower() or "错误" in stderr_output
            ):
                raise Exception(f"重启命令可能执行失败: {stderr_output}")
            else:
                self.logger.info(
                    f"{self.hostname}\t重启命令已发送（连接已断开，这是reboot命令的正常行为）"
                )

    def _wait_for_reboot_completion(self):
        """等待重启完成"""
        self.logger.info(
            f"{self.hostname}\t等待 {self.wait_time} 秒后开始检查SSH服务..."
        )
        time.sleep(self.wait_time)
        return self._wait_for_ssh()

    def _handle_ssh_exception(self, e):
        """处理SSH异常"""
        if isinstance(e, paramiko.AuthenticationException):
            self.logger.error(f"{self.hostname}\tSSH认证失败，请检查用户名和密钥")
        elif isinstance(e, paramiko.SSHException):
            self.logger.error(f"{self.hostname}\tSSH连接错误: {str(e)}")
        else:
            self.logger.error(
                f"{self.hostname}\t重启过程中发生错误: {str(e)}", exc_info=True
            )

    def reboot(self, hostname=None, wait_for_completion=True):
        """
        重启系统

        Args:
            hostname: 主机名（可选），如果不指定则使用初始化时设置的主机
            wait_for_completion: 是否等待重启完成

        Returns:
            bool: 重启是否成功
        """
        if hostname:
            self._set_host(hostname)

        if not self.host:
            raise ValueError("未指定要操作的主机，请在初始化或调用时指定hostname")

        try:
            self.logger.info(f"{self.hostname}\t正在连接到 {self.host}...")
            self.ssh = connect(self.host, self.user, self.password)
            self.logger.info(f"{self.hostname}\tSSH连接成功")

            self._get_system_info()

            # 执行重启命令（该方法会检查命令执行状态）
            try:
                self._execute_reboot_command()
            except Exception as e:
                self.logger.error(f"{self.hostname}\t重启命令执行失败: {str(e)}")
                raise

            self._safe_disconnect()

            # 命令执行成功的日志已在_execute_reboot_command中记录

            if wait_for_completion:
                return self._wait_for_reboot_completion()
            self.logger.info(f"{self.hostname}\t重启命令已发送，不等待完成")
            return True

        except (
            paramiko.AuthenticationException,
            paramiko.SSHException,
            Exception,
        ) as e:
            self._handle_ssh_exception(e)
            return False
        finally:
            self._safe_disconnect()

    def _safe_disconnect(self):
        """安全关闭SSH连接"""
        if self.ssh:
            try:
                disconnect(self.ssh)
            except Exception:
                pass
            self.ssh = None

    def verify_system_status(self, hostname=None):
        """
        验证系统状态

        Args:
            hostname: 主机名（可选），如果不指定则使用初始化时设置的主机

        Returns:
            dict: 包含系统状态信息的字典
        """
        if hostname:
            self._set_host(hostname)

        if not self.host:
            raise ValueError("未指定要操作的主机，请在初始化或调用时指定hostname")

        try:
            self.logger.info(f"{self.hostname}\t正在验证系统状态...")
            self.ssh = connect(self.host, self.user, self.password)

            status = {}
            try:
                # 获取系统运行时间
                uptime_result = command_execute(self.ssh, "uptime")
                status["uptime"] = uptime_result.strip()
                self.logger.info(
                    f"{self.hostname}\t系统运行时间: {uptime_result.strip()}"
                )
            except Exception as e:
                self.logger.warning(f"{self.hostname}\t无法获取运行时间: {str(e)}")

            try:
                # 获取系统时间
                date_result = command_execute(self.ssh, "date")
                status["datetime"] = date_result.strip()
                self.logger.info(f"{self.hostname}\t系统时间: {date_result.strip()}")
            except Exception as e:
                self.logger.warning(f"{self.hostname}\t无法获取系统时间: {str(e)}")

            try:
                # 获取系统信息
                uname_result = command_execute(self.ssh, "uname -a")
                status["system_info"] = uname_result.strip()
                self.logger.info(f"{self.hostname}\t系统信息: {uname_result.strip()}")
            except Exception as e:
                self.logger.warning(f"{self.hostname}\t无法获取系统信息: {str(e)}")

            self._safe_disconnect()
            return status

        except Exception as e:
            self.logger.error(f"{self.hostname}\t验证系统状态时发生错误: {str(e)}")
            self._safe_disconnect()
            return {}


def reboot_system(
    hostname, config_path="config/account.yaml", wait_for_completion=True
):
    """
    便捷函数：重启指定主机

    Args:
        hostname: 主机名（配置中的key）
        config_path: 配置文件路径
        wait_for_completion: 是否等待重启完成

    Returns:
        bool: 重启是否成功

    使用示例:
        from utils.reboot import reboot_system

        # 重启指定主机并等待完成
        success = reboot_system("z")

        # 只发送重启命令，不等待
        success = reboot_system("y", wait_for_completion=False)
    """
    manager = RebootManager(config_path, hostname=hostname)
    return manager.reboot(wait_for_completion=wait_for_completion)


def reboot_all_hosts(config_path="config/account.yaml", wait_for_completion=True):
    """
    便捷函数：重启所有主机

    Args:
        config_path: 配置文件路径
        wait_for_completion: 是否等待重启完成

    Returns:
        dict: 每个主机的重启结果 {hostname: success}

    使用示例:
        from utils.reboot import reboot_all_hosts

        # 重启所有主机并等待完成
        results = reboot_all_hosts()
    """
    manager = RebootManager(config_path)
    results = {}

    for hostname in manager.hosts.keys():
        try:
            success = manager.reboot(
                hostname=hostname, wait_for_completion=wait_for_completion
            )
            results[hostname] = success
        except Exception as e:
            manager.logger.error(f"{hostname}\t重启失败: {str(e)}")
            results[hostname] = False

    return results


if __name__ == "__main__":
    # 测试重启功能
    logger = get_logger()
    logger.info("=" * 50)
    logger.info("开始测试重启功能")
    logger.info("=" * 50)

    try:
        manager = RebootManager()

        # 获取所有主机
        all_hosts = list(manager.hosts.keys())
        logger.info(f"配置的主机: {all_hosts}")

        if not all_hosts:
            logger.error("配置中没有主机")
            exit(1)

        # 使用第一个主机进行测试
        test_hostname = all_hosts[0]
        logger.info(f"\n使用主机 '{test_hostname}' 进行测试")

        # 验证系统状态
        logger.info("\n1. 验证重启前系统状态:")
        status_before = manager.verify_system_status(hostname=test_hostname)

        # 执行重启
        logger.info("\n2. 执行重启操作:")
        success = manager.reboot(hostname=test_hostname, wait_for_completion=True)

        if success:
            # 验证重启后系统状态
            logger.info("\n3. 验证重启后系统状态:")
            status_after = manager.verify_system_status(hostname=test_hostname)

            logger.info("\n" + "=" * 50)
            logger.info("重启测试完成")
            logger.info("=" * 50)
        else:
            logger.error("重启失败")

    except Exception as e:
        logger.error(f"测试过程中发生错误: {str(e)}", exc_info=True)
