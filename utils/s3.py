"""
麒麟系统S3（挂起到内存）管理工具
通过SSH连接执行S3操作，并等待系统唤醒
"""

import time
import json
import os
import sys
import paramiko
from datetime import datetime

# 添加项目根目录到路径，以便导入utils模块
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from utils.connect import load_config, connect, disconnect, command_execute
from utils.logger import get_logger


class S3Manager:
    """
    麒麟系统S3（挂起到内存）管理工具
    通过SSH连接执行S3操作，并等待系统唤醒
    """

    def __init__(self, config_path="config/account.yaml", hostname=None):
        """
        初始化S3管理器

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
        self.wait_time = self.config.get(
            "s3_wait_time", 5
        )  # 等待SSH服务启动的时间（秒）
        self.s3_timeout = self.config.get(
            "s3_timeout", 300
        )  # S3唤醒超时时间（秒），默认5分钟

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
        等待SSH服务可用（系统唤醒后）

        Args:
            max_wait_time: 最大等待时间（秒），默认使用配置中的s3_timeout

        Returns:
            bool: SSH服务是否可用
        """
        if max_wait_time is None:
            max_wait_time = self.s3_timeout

        self.logger.info(
            f"{self.hostname}\t等待系统唤醒（SSH服务可用），最多等待 {max_wait_time} 秒..."
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
                    f"{self.hostname}\t系统已唤醒，SSH服务可用，耗时 {elapsed_time:.2f} 秒"
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
                        f"{self.hostname}\t系统尚未唤醒，已等待 {elapsed_time:.1f} 秒..."
                    )
                    last_log_time = elapsed_time
                time.sleep(check_interval)

        # 恢复paramiko日志级别
        paramiko_logger.setLevel(original_level)

        self.logger.error(
            f"{self.hostname}\t等待系统唤醒超时，已等待 {max_wait_time} 秒"
        )
        return False

    def _get_system_info(self):
        """获取系统信息"""
        try:
            uname_result = command_execute(self.ssh, "uname -a")
            self.logger.info(f"{self.hostname}\t系统信息: {uname_result.strip()}")
        except Exception as e:
            self.logger.warning(f"{self.hostname}\t无法获取系统信息: {str(e)}")

    def _check_user_permissions(self):
        """检查当前用户是否有S3权限"""
        try:
            whoami_result = command_execute(self.ssh, "whoami").strip()
            if whoami_result == "root":
                self.logger.info(f"{self.hostname}\t当前用户是root，无需sudo")
                return False  # 不需要sudo

            # 检查是否有sudo权限且无需密码
            try:
                stdin, stdout, stderr = self.ssh.exec_command(
                    "sudo -n systemctl suspend 2>&1", timeout=2
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

    def _execute_s3_command(self):
        """执行S3命令并确认执行状态"""
        self.logger.info(f"{self.hostname}\t正在执行S3（挂起到内存）命令...")

        # 检查是否需要sudo
        need_sudo = self._check_user_permissions()

        # 尝试多种S3命令方式
        s3_commands = []
        if need_sudo:
            s3_commands = [
                "sudo -S systemctl suspend",
                "sudo -S rtcwake -m mem -s 30",  # 30秒后自动唤醒
                "sudo -S sh -c 'echo mem > /sys/power/state'",
            ]
        else:
            s3_commands = [
                "systemctl suspend",
                "rtcwake -m mem -s 30",
                "sh -c 'echo mem > /sys/power/state'",
            ]

        last_error = None
        for command in s3_commands:
            try:
                if need_sudo and "-S" in command:
                    self.logger.info(
                        f"{self.hostname}\t尝试使用sudo执行S3命令: {command.split()[1]}"
                    )
                else:
                    self.logger.info(f"{self.hostname}\t尝试执行S3命令: {command}")

                stdin, stdout, stderr = self.ssh.exec_command(command, timeout=5)

                # 如果需要sudo，通过stdin传递密码
                if need_sudo and "-S" in command:
                    try:
                        stdin.write(f"{self.password}\n")
                        stdin.flush()
                        stdin.channel.shutdown_write()
                    except Exception as e:
                        self.logger.debug(
                            f"{self.hostname}\t写入密码时出错（可能命令已执行）: {str(e)}"
                        )

                # 等待命令开始执行（S3命令执行后连接会断开）
                exit_status = None
                stdout_output = ""
                stderr_output = ""

                try:
                    # 尝试读取输出（可能为空，因为S3会立即挂起）
                    stdout_output = (
                        stdout.read().decode("utf-8", errors="ignore").strip()
                    )
                    stderr_output = (
                        stderr.read().decode("utf-8", errors="ignore").strip()
                    )

                    # 等待命令状态（S3通常不会返回，连接会断开）
                    try:
                        exit_status = stdout.channel.recv_exit_status()
                    except Exception:
                        # 对于S3命令，连接断开是正常的，exit_status可能无法获取
                        pass

                except Exception as e:
                    # 连接断开是S3命令的正常行为
                    self.logger.debug(
                        f"{self.hostname}\t读取命令输出时连接断开（这是正常的）: {str(e)}"
                    )

                # 检查命令执行结果
                if exit_status is not None:
                    if exit_status == 0:
                        self.logger.info(
                            f"{self.hostname}\tS3命令执行成功（退出码: {exit_status}）"
                        )
                        return True
                    else:
                        self.logger.warning(
                            f"{self.hostname}\tS3命令执行失败（退出码: {exit_status}），尝试下一个命令"
                        )
                        last_error = f"退出码: {exit_status}"
                        continue
                else:
                    # 如果没有退出码，检查是否有错误输出
                    if stderr_output and (
                        "permission denied" in stderr_output.lower()
                        or "错误" in stderr_output
                    ):
                        self.logger.warning(
                            f"{self.hostname}\tS3命令可能执行失败: {stderr_output}，尝试下一个命令"
                        )
                        last_error = stderr_output
                        continue
                    else:
                        # 连接断开通常是S3成功的标志
                        self.logger.info(
                            f"{self.hostname}\tS3命令已发送（连接已断开，这是S3命令的正常行为）"
                        )
                        return True

            except Exception as e:
                self.logger.debug(
                    f"{self.hostname}\t执行S3命令 '{command}' 时出错: {str(e)}，尝试下一个命令"
                )
                last_error = str(e)
                continue

        # 所有命令都失败了
        raise Exception(f"所有S3命令都执行失败，最后一个错误: {last_error}")

    def _verify_s3_entered(self, s3_start_time=None):
        """
        验证S3是否真正生效（系统是否真的进入了S3状态）

        注意：只检查S3开始执行之后的新日志记录，避免受到之前S3操作的影响

        Args:
            s3_start_time: S3开始执行的时间戳（datetime对象或时间戳字符串），用于只检查该时间之后的日志

        Returns:
            tuple: (bool, str) - (是否进入S3, 验证信息)
        """
        try:
            self.logger.info(f"{self.hostname}\t正在验证S3是否真正生效...")
            self.ssh = connect(self.host, self.user, self.password)

            verification_results = []

            # 计算时间范围：如果提供了S3开始时间，只检查该时间之后的日志
            # 否则检查最近30秒内的日志（避免检查到之前S3的记录）
            if s3_start_time:
                # 将时间戳转换为适合journalctl的格式
                if isinstance(s3_start_time, datetime):
                    time_str = s3_start_time.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    time_str = str(s3_start_time)
                time_filter = f"--since '{time_str}'"
                time_desc = f"S3开始时间({time_str})之后"
            else:
                # 默认只检查最近30秒内的日志（避免检查到之前S3的记录）
                time_filter = "--since '30 seconds ago'"
                time_desc = "最近30秒内"

            # 方法1: 检查dmesg日志中是否有suspend/resume记录
            # 注意：为了避免检查到之前S3的记录，我们使用dmesg -T获取时间戳并进行过滤
            try:
                # 使用dmesg -T获取带时间戳的输出
                # 先获取更多记录，然后根据时间戳过滤
                dmesg_cmd = "dmesg -T 2>/dev/null | grep -iE '(suspend|resume|s3|s3_state)' | tail -10"
                dmesg_result = command_execute(self.ssh, dmesg_cmd).strip()
                if dmesg_result:
                    # 如果提供了S3开始时间，解析dmesg的时间戳进行精确过滤
                    if s3_start_time and isinstance(s3_start_time, datetime):
                        # 解析dmesg -T输出格式: [Mon Jan 01 12:00:00 2024] ...
                        # 提取时间戳并与S3开始时间比较，只保留S3开始时间之后的记录
                        lines = dmesg_result.split("\n")
                        recent_lines = []
                        import re

                        for line in lines:
                            if not line.strip():
                                continue
                            try:
                                # 提取时间戳部分 [Mon Jan 01 12:00:00 2024]
                                timestamp_match = re.search(r"\[(.*?)\]", line)
                                if timestamp_match:
                                    timestamp_str = timestamp_match.group(1)
                                    # 解析时间戳（格式：Mon Jan 01 12:00:00 2024）
                                    try:
                                        dmesg_time = datetime.strptime(
                                            timestamp_str, "%a %b %d %H:%M:%S %Y"
                                        )
                                        # 只保留S3开始时间之后的记录（加上5秒容差，因为命令执行需要时间）
                                        from datetime import timedelta

                                        if dmesg_time >= (
                                            s3_start_time - timedelta(seconds=5)
                                        ):
                                            recent_lines.append(line)
                                            self.logger.info(
                                                f"{self.hostname}\t✓ dmesg时间戳验证通过"
                                            )
                                    except ValueError:
                                        # 如果时间解析失败，跳过该行
                                        pass
                            except Exception:
                                # 解析失败，跳过该行
                                pass

                        if recent_lines:
                            recent_result = "\n".join(recent_lines)
                            if (
                                "suspend" in recent_result.lower()
                                or "s3" in recent_result.lower()
                            ):
                                verification_results.append(
                                    "✓ dmesg显示有suspend记录（本次S3）"
                                )
                                self.logger.info(
                                    f"{self.hostname}\t✓ dmesg验证通过: 发现本次S3的suspend记录"
                                )
                            else:
                                verification_results.append(
                                    "⚠ dmesg未发现本次S3的suspend记录"
                                )
                        else:
                            verification_results.append(
                                "⚠ dmesg无本次S3时间范围内的suspend记录"
                            )
                    else:
                        # 没有时间戳，只检查最后3条记录（假设是最新的）
                        # 这种方式不够准确，但至少避免检查到很久之前的记录
                        last_lines = dmesg_result.split("\n")[-3:]
                        last_result = "\n".join(last_lines)
                        if (
                            "suspend" in last_result.lower()
                            or "s3" in last_result.lower()
                        ):
                            verification_results.append(
                                "✓ dmesg显示有suspend记录（最新记录）"
                            )
                            self.logger.info(
                                f"{self.hostname}\t✓ dmesg验证通过: 发现最新的suspend记录"
                            )
                        else:
                            verification_results.append(
                                "⚠ dmesg未发现最新的suspend记录"
                            )
                            self.logger.warning(
                                f"{self.hostname}\t⚠ dmesg验证: 未发现最新的suspend记录"
                            )
                else:
                    verification_results.append("⚠ dmesg无suspend相关记录")
                    self.logger.warning(
                        f"{self.hostname}\t⚠ dmesg验证: 无suspend相关记录"
                    )
            except Exception as e:
                self.logger.debug(f"{self.hostname}\t检查dmesg时出错: {str(e)}")

            # 方法2: 检查journalctl日志（systemd系统）
            # 使用时间过滤，只检查S3开始之后的日志
            try:
                journal_cmd = f"journalctl {time_filter} | grep -iE '(suspend|resume|s3)' | tail -3"
                journal_result = command_execute(self.ssh, journal_cmd).strip()
                if journal_result:
                    if (
                        "suspend" in journal_result.lower()
                        or "s3" in journal_result.lower()
                    ):
                        verification_results.append(
                            f"✓ journalctl显示有suspend记录（{time_desc}）"
                        )
                        self.logger.info(
                            f"{self.hostname}\t✓ journalctl验证通过: 发现{time_desc}的suspend记录"
                        )
                    else:
                        verification_results.append(
                            f"⚠ journalctl未发现{time_desc}的suspend记录"
                        )
                else:
                    verification_results.append(
                        f"⚠ journalctl无{time_desc}的suspend相关记录"
                    )
            except Exception as e:
                self.logger.debug(f"{self.hostname}\t检查journalctl时出错: {str(e)}")

            # 方法3: 检查/proc/acpi/wakeup或/sys/power目录状态
            try:
                # 检查是否有power相关的设备信息
                power_state_cmd = "cat /sys/power/state 2>/dev/null || echo 'N/A'"
                power_state = command_execute(self.ssh, power_state_cmd).strip()
                if "mem" in power_state.lower():
                    verification_results.append("✓ /sys/power/state包含mem（S3支持）")
                    self.logger.info(
                        f"{self.hostname}\t✓ /sys/power/state验证: {power_state}"
                    )
            except Exception as e:
                self.logger.debug(
                    f"{self.hostname}\t检查/sys/power/state时出错: {str(e)}"
                )

            self._safe_disconnect()

            # 判断验证结果
            success_count = sum(1 for r in verification_results if r.startswith("✓"))
            if success_count > 0:
                verification_msg = "; ".join(verification_results)
                self.logger.info(
                    f"{self.hostname}\tS3验证通过 ({success_count}/{len(verification_results)}项通过): {verification_msg}"
                )
                return True, verification_msg
            else:
                verification_msg = (
                    "; ".join(verification_results)
                    if verification_results
                    else "未找到S3证据"
                )
                self.logger.warning(
                    f"{self.hostname}\tS3验证未通过: {verification_msg}"
                )
                return False, verification_msg

        except Exception as e:
            self.logger.warning(f"{self.hostname}\t验证S3时出错: {str(e)}")
            self._safe_disconnect()
            return False, f"验证过程出错: {str(e)}"

    def _wait_for_s3_completion(self, s3_start_time=None):
        """
        等待S3完成（系统唤醒）并验证S3是否生效

        Args:
            s3_start_time: S3开始执行的时间戳（用于验证时只检查S3之后的新日志）
        """
        # 先等待一段时间，让系统完全进入S3状态
        self.logger.info(f"{self.hostname}\t等待系统进入S3状态...")
        time.sleep(self.wait_time)

        # 然后等待系统唤醒
        ssh_ready = self._wait_for_ssh()

        if ssh_ready:
            # 系统唤醒后，验证S3是否真正生效
            # 只检查S3开始之后的新日志记录
            s3_verified, verification_msg = self._verify_s3_entered(s3_start_time)
            if not s3_verified:
                self.logger.warning(
                    f"{self.hostname}\t警告: 系统已唤醒，但未找到S3生效的证据。"
                    f"这可能表示S3命令未真正执行，或者系统日志不完整。"
                    f"验证信息: {verification_msg}"
                )
            return ssh_ready
        else:
            return False

    def _safe_disconnect(self):
        """安全关闭SSH连接"""
        if self.ssh:
            try:
                disconnect(self.ssh)
            except Exception:
                pass
            self.ssh = None

    def s3(self, hostname=None, wait_for_completion=True):
        """
        执行S3（挂起到内存）

        Args:
            hostname: 主机名（可选），如果不指定则使用初始化时设置的主机
            wait_for_completion: 是否等待系统唤醒

        Returns:
            bool: S3是否成功
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

            # 记录S3开始时间，用于后续验证时只检查本次S3的日志（避免受到之前S3记录的影响）
            s3_start_time = datetime.now()

            # 执行S3命令（该方法会检查命令执行状态）
            try:
                self._execute_s3_command()
            except Exception as e:
                self.logger.error(f"{self.hostname}\tS3命令执行失败: {str(e)}")
                raise

            self._safe_disconnect()

            if wait_for_completion:
                return self._wait_for_s3_completion(s3_start_time)
            self.logger.info(f"{self.hostname}\tS3命令已发送，不等待完成")
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

    def _handle_ssh_exception(self, e):
        """处理SSH异常"""
        if isinstance(e, paramiko.AuthenticationException):
            self.logger.error(f"{self.hostname}\tSSH认证失败: {str(e)}")
        elif isinstance(e, paramiko.SSHException):
            self.logger.error(f"{self.hostname}\tSSH连接错误: {str(e)}")
        else:
            self.logger.error(
                f"{self.hostname}\tS3过程中发生错误: {str(e)}", exc_info=True
            )

    def verify_system_status(self, hostname=None):
        """
        验证系统状态

        Args:
            hostname: 主机名（可选）

        Returns:
            dict: 系统状态信息
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
                uptime_result = command_execute(self.ssh, "uptime")
                status["uptime"] = uptime_result.strip()
                self.logger.info(
                    f"{self.hostname}\t系统运行时间: {uptime_result.strip()}"
                )
            except Exception as e:
                self.logger.warning(f"{self.hostname}\t无法获取uptime: {str(e)}")

            try:
                date_result = command_execute(self.ssh, "date")
                status["datetime"] = date_result.strip()
                self.logger.info(f"{self.hostname}\t系统时间: {date_result.strip()}")
            except Exception as e:
                self.logger.warning(f"{self.hostname}\t无法获取date: {str(e)}")

            try:
                uname_result = command_execute(self.ssh, "uname -a")
                status["system_info"] = uname_result.strip()
                self.logger.info(f"{self.hostname}\t系统信息: {uname_result.strip()}")
            except Exception as e:
                self.logger.warning(f"{self.hostname}\t无法获取uname: {str(e)}")

            self._safe_disconnect()
            return status
        except Exception as e:
            self.logger.error(f"{self.hostname}\t验证系统状态时发生错误: {str(e)}")
            self._safe_disconnect()
            return {}


def s3_system(hostname, config_path="config/account.yaml", wait_for_completion=True):
    """
    便捷函数：对指定主机执行S3

    Args:
        hostname: 主机名（配置中的key）
        config_path: 配置文件路径
        wait_for_completion: 是否等待系统唤醒

    Returns:
        bool: S3是否成功

    使用示例:
        from utils.s3 import s3_system

        # 执行S3并等待系统唤醒
        success = s3_system("z")

        # 只发送S3命令，不等待
        success = s3_system("y", wait_for_completion=False)
    """
    manager = S3Manager(config_path, hostname=hostname)
    return manager.s3(wait_for_completion=wait_for_completion)


def s3_all_hosts(config_path="config/account.yaml", wait_for_completion=True):
    """
    便捷函数：对所有主机执行S3

    Args:
        config_path: 配置文件路径
        wait_for_completion: 是否等待系统唤醒

    Returns:
        dict: 每个主机的S3结果 {hostname: success}

    使用示例:
        from utils.s3 import s3_all_hosts

        # 对所有主机执行S3并等待唤醒
        results = s3_all_hosts()
    """
    manager = S3Manager(config_path)
    results = {}

    for hostname in manager.hosts.keys():
        try:
            success = manager.s3(
                hostname=hostname, wait_for_completion=wait_for_completion
            )
            results[hostname] = success
        except Exception as e:
            manager.logger.error(f"{hostname}\tS3失败: {str(e)}")
            results[hostname] = False

    return results


if __name__ == "__main__":
    # 测试S3功能
    logger = get_logger()
    logger.info("=" * 50)
    logger.info("开始测试S3功能")
    logger.info("=" * 50)

    try:
        manager = S3Manager()

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
        logger.info("\n1. 验证S3前系统状态:")
        status_before = manager.verify_system_status(hostname=test_hostname)

        # 执行S3
        logger.info("\n2. 执行S3操作:")
        success = manager.s3(hostname=test_hostname, wait_for_completion=True)

        if success:
            # 验证S3后系统状态
            logger.info("\n3. 验证S3后系统状态:")
            status_after = manager.verify_system_status(hostname=test_hostname)

            logger.info("\n" + "=" * 50)
            logger.info("S3测试完成")
            logger.info("=" * 50)
        else:
            logger.error("S3失败")

    except Exception as e:
        logger.error(f"测试过程中发生错误: {str(e)}", exc_info=True)
