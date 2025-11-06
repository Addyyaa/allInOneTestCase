"""
500次循环S4（休眠到磁盘）测试脚本 - 支持多台机器并行测试

测试用例：麒麟系统P10 S4（休眠到磁盘）500次循环测试

测试规则：
- 自动要求2台机器运行500次循环（可配置）
- 允许有1次非Critical且S4可恢复的Fail（包括蓝屏、黑屏、系统Hang住等）
- 不允许有Critical及S4无法恢复的Fail

测试步骤（实现方式）：
1. 初始化阶段：
   - 加载配置文件（config/account.yaml），读取主机信息、用户凭证、循环次数等
   - 初始化S4Manager管理器，建立SSH连接准备
   - 验证初始系统状态（uptime、date、uname）

2. 循环测试阶段（500次）：
   对于每次循环（1到500）：
   a) SSH连接：
      - 通过SSH连接到目标主机（使用配置的用户名和密码）
      - 获取系统信息并记录日志

   b) 执行S4命令：
      - 检测用户权限（是否需要sudo）
      - 尝试多种S4命令方式（按优先级顺序）：
        * rtcwake -m disk -s <延迟秒数>（RTC定时唤醒，支持自动唤醒）
        * systemctl hibernate（systemd方式）
        * echo disk > /sys/power/state（直接写入power/state）
      - S4命令执行后SSH连接会断开（这是正常行为）

   c) 等待系统唤醒：
      - 持续检测SSH服务是否可用（最多等待s4_timeout秒）
      - 每10秒记录一次等待日志
      - 系统唤醒后，等待s4_wait_time秒让系统完全恢复（SSH服务稳定、系统服务就绪）
      - 重新建立SSH连接并验证系统状态

   d) 验证S4是否生效：
      - 系统唤醒后，通过多种方式验证S4是否真正生效：
        * 检查dmesg日志中的hibernate/resume记录（最近1分钟内的日志）
        * 检查journalctl日志（systemd系统）中的hibernate记录
        * 检查/sys/power/state文件确认S4支持（disk状态）
      - 如果未找到S4生效的证据，记录警告（可能是日志不完整或S4未真正执行）
      - 验证结果会记录在日志中，包括通过/未通过的验证项

   e) 验证系统状态：
      - 连接成功后验证系统状态（uptime、date、uname）
      - 记录本次S4的耗时（从开始到唤醒完成）

   f) 错误处理：
      - 如果S4失败，进行错误分类：
        * Critical错误：认证失败、权限错误、配置错误等 → 立即停止测试
        * 非Critical可恢复错误：连接被拒绝等临时网络问题 → 尝试恢复检测
        * 非Critical不可恢复错误：超时、SSH服务未就绪等 → 立即停止测试
      - 对于可恢复错误，等待30秒后尝试重新连接验证，如果失败则尝试强制S4
      - 记录失败的详细信息（错误类型、耗时、时间戳等）

3. 多机并行测试：
   - 如果配置了多台主机，使用多线程并行执行测试
   - 每台主机独立运行500次循环
   - 使用全局锁确保线程安全
   - 如果任何一台主机检测到Critical或不可恢复错误，所有线程停止

4. 统计和报告：
   - 记录每台主机的统计信息：
     * 成功次数、失败次数
     * Critical失败次数
     * 非Critical可恢复失败次数
     * 非Critical不可恢复失败次数
     * 每次S4的详细耗时（成功和失败都记录）
   - 每10次循环输出一次进度统计
   - 测试结束后生成最终报告

5. 报告生成：
   - 自动生成HTML报告（包含汇总统计、每台主机详细统计、每次S4耗时详情）
   - 自动生成Excel报告（包含汇总统计表和每台主机的详细数据）
   - 报告文件保存在reports/目录下

预期结果：
1. 测试通过标准：
   - 所有500次S4操作均成功完成，系统能够正常唤醒
   - 或者最多允许1次非Critical且可恢复的失败（如临时网络问题）
   - 不允许有任何Critical失败
   - 不允许有任何不可恢复的失败（如系统蓝屏、死机等）

2. 系统行为：
   - 每次S4后系统能够正常唤醒（在s4_timeout时间内）
   - SSH服务能够正常恢复
   - 系统状态信息（uptime、date、uname）能够正常获取
   - 系统不会出现蓝屏、黑屏、死机等严重问题

3. 性能指标：
   - 记录每次S4的耗时（从开始到唤醒完成）
   - 统计平均耗时、最小耗时、最大耗时
   - 区分成功和失败的耗时统计

4. 报告输出：
   - 控制台输出详细的测试日志和最终统计报告
   - 生成HTML格式的测试报告（包含所有统计信息和每次S4的详情）
   - 生成Excel格式的测试报告（包含汇总统计和详细数据表）

5. 失败处理：
   - 遇到Critical错误或不可恢复错误时，立即停止测试并报告失败
   - 遇到可恢复错误时，尝试自动恢复，恢复成功则继续测试
   - 所有失败信息都会详细记录在日志和报告中
"""

import os
import sys
import time
import threading
from datetime import datetime
from enum import Enum

# 添加项目根目录到路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from utils.s4 import S4Manager
from utils.logger import get_logger


class FailureType(Enum):
    """失败类型枚举"""

    CRITICAL = "critical"  # Critical错误：无法恢复
    NON_CRITICAL_RECOVERABLE = "non_critical_recoverable"  # 非Critical且可恢复
    NON_CRITICAL_UNRECOVERABLE = "non_critical_unrecoverable"  # 非Critical但不可恢复


class FailureInfo:
    """失败信息类"""

    def __init__(self, cycle, hostname, error, failure_type, recoverable=False):
        self.cycle = cycle
        self.hostname = hostname
        self.error = str(error)
        self.failure_type = failure_type
        self.recoverable = recoverable
        self.timestamp = datetime.now()
        self.duration = 0


class S4CycleTest:
    """循环S4测试类 - 支持多台机器并行测试"""

    def __init__(
        self, config_path="config/account.yaml", total_cycles=None, required_hosts=None
    ):
        """
        初始化测试

        Args:
            config_path: 配置文件路径
            total_cycles: 总循环次数（可选），如果不指定则从配置文件读取
            required_hosts: 需要的机器数量（可选），如果不指定则使用配置中的所有主机
        """
        self.manager = S4Manager(config_path)
        self.logger = get_logger()

        # 如果未指定total_cycles，从配置文件读取
        if total_cycles is None:
            total_cycles = self.manager.config.get("total_cycles", 500)
            self.logger.info(f"从配置文件读取循环次数: {total_cycles}")

        self.total_cycles = total_cycles

        # 获取所有主机
        all_hosts = list(self.manager.hosts.keys())
        if not all_hosts:
            raise ValueError("配置中没有主机")

        # 确定要使用的主机
        if required_hosts is None:
            # 如果不指定，使用所有配置的主机
            self.hostnames = all_hosts
            self.required_hosts = len(all_hosts)
        else:
            # 如果指定了数量，使用前N台
            if len(all_hosts) < required_hosts:
                self.logger.warning(
                    f"配置中只有 {len(all_hosts)} 台主机，但要求 {required_hosts} 台，"
                    f"将使用所有 {len(all_hosts)} 台主机进行测试"
                )
                self.hostnames = all_hosts
                self.required_hosts = len(all_hosts)
            else:
                self.hostnames = all_hosts[:required_hosts]
                self.required_hosts = required_hosts

        self.logger.info(
            f"将使用以下 {len(self.hostnames)} 台主机进行测试: {self.hostnames}"
        )

        # 统计信息（每台机器一个）
        self.stats = {}
        for hostname in self.hostnames:
            self.stats[hostname] = {
                "total": 0,
                "success": 0,
                "failed": 0,
                "critical_failures": 0,
                "non_critical_recoverable_failures": 0,
                "non_critical_unrecoverable_failures": 0,
                "start_time": None,
                "end_time": None,
                "failures": [],  # 记录失败的信息
                "cycle_durations": [],  # 记录每次S4的耗时（成功和失败都记录）
            }

        # 全局统计
        self.global_stats = {
            "start_time": None,
            "end_time": None,
            "lock": threading.Lock(),  # 用于线程安全
        }

    def _classify_error(self, error, hostname):
        """
        分类错误类型

        Args:
            error: 错误对象或字符串
            hostname: 主机名

        Returns:
            tuple: (FailureType, bool) - (失败类型, 是否可恢复)
        """
        error_str = str(error).lower()

        # Critical错误：认证失败、权限错误、配置错误等无法恢复的
        critical_keywords = [
            "authentication",
            "认证失败",
            "permission denied",
            "权限不足",
            "password required",
            "密码",
            "config",
            "配置",
            "valueerror",
            "未指定",
        ]

        if any(keyword in error_str for keyword in critical_keywords):
            return FailureType.CRITICAL, False

        # 非Critical但可恢复的错误：连接被拒绝等临时网络问题
        recoverable_keywords = [
            "connection refused",
            "no route to host",
            "network is unreachable",
        ]

        if any(keyword in error_str for keyword in recoverable_keywords):
            # 这些错误可能是S4过程中的临时网络问题，可以尝试恢复
            return FailureType.NON_CRITICAL_RECOVERABLE, True

        # 非Critical但不可恢复的错误：超时、SSH服务未就绪等
        # 这些通常表示系统蓝屏、死机等严重问题
        unrecoverable_keywords = [
            "unable to connect",
            "connection timeout",
            "timed out",
            "ssh服务",
            "等待系统唤醒超时",
            "S4失败",
            "error reading ssh protocol banner",
            "eoferror",
        ]

        if any(keyword in error_str for keyword in unrecoverable_keywords):
            # 超时通常表示系统蓝屏、死机等严重问题，不可恢复
            return FailureType.NON_CRITICAL_UNRECOVERABLE, False

        # 其他错误默认为非Critical但不可恢复
        return FailureType.NON_CRITICAL_UNRECOVERABLE, False

    def _check_recoverable(self, hostname, failure_info):
        """
        检查故障是否可以通过S4恢复

        Args:
            hostname: 主机名
            failure_info: 失败信息

        Returns:
            bool: 是否可恢复
        """
        self.logger.info(f"{hostname}\t尝试检测故障是否可恢复...")

        # 等待一段时间后尝试重新连接
        time.sleep(30)  # 给系统一些恢复时间

        max_retries = 3
        for retry in range(max_retries):
            try:
                # 尝试连接并验证系统状态
                status = self.manager.verify_system_status(hostname=hostname)
                if status:
                    self.logger.info(f"{hostname}\t✓ 故障已恢复，系统可以正常连接")
                    return True
            except Exception as e:
                self.logger.debug(
                    f"{hostname}\t第 {retry + 1} 次恢复检测失败: {str(e)}"
                )
                if retry < max_retries - 1:
                    time.sleep(10)

        # 如果无法恢复，尝试强制S4
        self.logger.warning(f"{hostname}\t常规恢复失败，尝试强制S4...")
        try:
            success = self.manager.s4(hostname=hostname, wait_for_completion=True)
            if success:
                self.logger.info(f"{hostname}\t✓ 强制S4成功，故障已恢复")
                return True
        except Exception as e:
            self.logger.error(f"{hostname}\t✗ 强制S4也失败: {str(e)}")

        self.logger.error(f"{hostname}\t✗ 故障无法恢复")
        return False

    def _run_single_host_test(self, hostname):
        """在单台主机上运行循环S4测试"""
        self.logger.info(f"\n{'='*80}")
        self.logger.info(f"开始测试主机: {hostname}")
        self.logger.info(f"{'='*80}")

        self.stats[hostname]["start_time"] = datetime.now()

        for cycle in range(1, self.total_cycles + 1):
            with self.global_stats["lock"]:
                # 检查全局是否应该停止（如果已经有Critical错误或不可恢复错误）
                if self._has_critical_failure():
                    self.logger.warning(f"{hostname}\t检测到Critical错误，停止测试")
                    break
                if self._has_unrecoverable_failure():
                    self.logger.warning(f"{hostname}\t检测到不可恢复错误，停止测试")
                    break

            self.logger.info(f"\n{hostname}\t第 {cycle}/{self.total_cycles} 次S4测试")

            cycle_start_time = time.time()
            self.stats[hostname]["total"] = cycle

            try:
                # 执行S4
                success = self.manager.s4(hostname=hostname, wait_for_completion=True)

                if success:
                    self.stats[hostname]["success"] += 1
                    cycle_duration = time.time() - cycle_start_time
                    # 记录成功的S4耗时
                    self.stats[hostname]["cycle_durations"].append(
                        {
                            "cycle": cycle,
                            "duration": cycle_duration,
                            "status": "success",
                            "timestamp": datetime.now(),
                        }
                    )
                    self.logger.info(
                        f"{hostname}\t✓ 第 {cycle} 次S4成功，耗时 {cycle_duration:.2f} 秒"
                    )

                    # 验证S4后系统状态
                    try:
                        status = self.manager.verify_system_status(hostname=hostname)
                        self.logger.debug(f"{hostname}\tS4后系统状态: {status}")
                    except Exception as e:
                        self.logger.warning(
                            f"{hostname}\t第 {cycle} 次S4后验证系统状态失败: {str(e)}"
                        )

                else:
                    # S4失败
                    cycle_duration = time.time() - cycle_start_time
                    error_msg = "S4失败（返回False）"
                    failure_type, is_recoverable = self._classify_error(
                        error_msg, hostname
                    )

                    # 对于可恢复的错误，尝试恢复检测
                    if failure_type == FailureType.NON_CRITICAL_RECOVERABLE:
                        self.logger.info(
                            f"{hostname}\t第 {cycle} 次S4失败，尝试恢复检测..."
                        )
                        is_recoverable = self._check_recoverable(hostname, None)
                        # 如果恢复检测失败，更新为不可恢复
                        if not is_recoverable:
                            failure_type = FailureType.NON_CRITICAL_UNRECOVERABLE

                    failure_info = FailureInfo(
                        cycle, hostname, error_msg, failure_type, is_recoverable
                    )
                    failure_info.duration = cycle_duration

                    # 记录失败的S4耗时
                    self.stats[hostname]["cycle_durations"].append(
                        {
                            "cycle": cycle,
                            "duration": cycle_duration,
                            "status": "failed",
                            "error": error_msg,
                            "failure_type": failure_type.value,
                            "timestamp": datetime.now(),
                        }
                    )

                    self._record_failure(hostname, failure_info)

                    # Critical错误或不可恢复的错误都应该停止测试
                    if failure_type == FailureType.CRITICAL:
                        self.logger.error(f"{hostname}\t检测到Critical失败，停止测试")
                        break

                    if not is_recoverable:
                        self.logger.error(
                            f"{hostname}\t检测到不可恢复的失败（设备可能蓝屏/死机），停止测试"
                        )
                        break

            except Exception as e:
                cycle_duration = time.time() - cycle_start_time
                failure_type, is_recoverable = self._classify_error(e, hostname)

                # 对于可恢复的错误，尝试恢复检测
                if failure_type == FailureType.NON_CRITICAL_RECOVERABLE:
                    self.logger.info(
                        f"{hostname}\t第 {cycle} 次S4异常，尝试恢复检测..."
                    )
                    is_recoverable = self._check_recoverable(hostname, None)
                    # 如果恢复检测失败，更新为不可恢复
                    if not is_recoverable:
                        failure_type = FailureType.NON_CRITICAL_UNRECOVERABLE

                failure_info = FailureInfo(
                    cycle, hostname, e, failure_type, is_recoverable
                )
                failure_info.duration = cycle_duration

                # 记录异常S4的耗时
                self.stats[hostname]["cycle_durations"].append(
                    {
                        "cycle": cycle,
                        "duration": cycle_duration,
                        "status": "failed",
                        "error": str(e),
                        "failure_type": failure_type.value,
                        "timestamp": datetime.now(),
                    }
                )

                self._record_failure(hostname, failure_info)

                # Critical错误或不可恢复的错误都应该停止测试
                if failure_type == FailureType.CRITICAL:
                    self.logger.error(f"{hostname}\t检测到Critical失败，停止测试")
                    break

                if not is_recoverable:
                    self.logger.error(
                        f"{hostname}\t检测到不可恢复的失败（设备可能蓝屏/死机），停止测试"
                    )
                    break

            # 每10次输出一次统计信息
            if cycle % 10 == 0:
                self._print_progress(hostname)

            # 每次S4后短暂等待
            if cycle < self.total_cycles:
                time.sleep(2)

        self.stats[hostname]["end_time"] = datetime.now()

    def _record_failure(self, hostname, failure_info):
        """记录失败信息"""
        self.stats[hostname]["failed"] += 1
        self.stats[hostname]["failures"].append(failure_info)

        if failure_info.failure_type == FailureType.CRITICAL:
            self.stats[hostname]["critical_failures"] += 1
            self.logger.error(
                f"{hostname}\t✗ 第 {failure_info.cycle} 次S4失败 [CRITICAL]: {failure_info.error}"
            )
        elif failure_info.recoverable:
            self.stats[hostname]["non_critical_recoverable_failures"] += 1
            self.logger.warning(
                f"{hostname}\t⚠ 第 {failure_info.cycle} 次S4失败 [Non-Critical, Recoverable]: {failure_info.error}"
            )
        else:
            self.stats[hostname]["non_critical_unrecoverable_failures"] += 1
            self.logger.error(
                f"{hostname}\t✗ 第 {failure_info.cycle} 次S4失败 [Non-Critical, Unrecoverable]: {failure_info.error}"
            )

    def _has_critical_failure(self):
        """检查是否有Critical失败"""
        for hostname in self.hostnames:
            if self.stats[hostname]["critical_failures"] > 0:
                return True
        return False

    def _has_unrecoverable_failure(self):
        """检查是否有不可恢复的失败"""
        for hostname in self.hostnames:
            if self.stats[hostname]["non_critical_unrecoverable_failures"] > 0:
                return True
        return False

    def run_test(self):
        """运行单台或多台机器的循环S4测试（多台时并行）"""
        self.logger.info("=" * 80)
        if len(self.hostnames) == 1:
            self.logger.info(f"开始500次循环S4测试（单台机器）")
        else:
            self.logger.info(f"开始500次循环S4测试（{len(self.hostnames)}台机器并行）")
        self.logger.info(f"测试主机: {self.hostnames}")
        self.logger.info(f"总循环次数: {self.total_cycles}")
        self.logger.info("=" * 80)

        self.global_stats["start_time"] = datetime.now()
        start_timestamp = time.time()

        # 验证初始系统状态
        self.logger.info("\n" + "-" * 80)
        self.logger.info("验证初始系统状态...")
        for hostname in self.hostnames:
            try:
                initial_status = self.manager.verify_system_status(hostname=hostname)
                self.logger.info(f"{hostname}\t初始系统状态: {initial_status}")
            except Exception as e:
                self.logger.warning(f"{hostname}\t无法获取初始系统状态: {str(e)}")

        # 如果只有1台机器，直接运行（不使用线程）
        if len(self.hostnames) == 1:
            self._run_single_host_test(self.hostnames[0])
        else:
            # 多台机器时使用线程并行运行测试
            threads = []
            for hostname in self.hostnames:
                thread = threading.Thread(
                    target=self._run_single_host_test, args=(hostname,), daemon=False
                )
                threads.append(thread)
                thread.start()

            # 等待所有线程完成
            for thread in threads:
                thread.join()

        self.global_stats["end_time"] = datetime.now()
        success = self._print_final_report(start_timestamp)
        # 生成报告
        self._generate_reports()
        return success

    def _print_progress(self, hostname):
        """打印单台主机的进度信息"""
        stats = self.stats[hostname]
        success_rate = (
            (stats["success"] / stats["total"] * 100) if stats["total"] > 0 else 0
        )
        self.logger.info(f"\n{hostname} 进度统计:")
        self.logger.info(f"  已完成: {stats['total']}/{self.total_cycles}")
        self.logger.info(f"  成功: {stats['success']}")
        self.logger.info(f"  失败: {stats['failed']}")
        self.logger.info(f"  Critical失败: {stats['critical_failures']}")
        self.logger.info(
            f"  非Critical可恢复失败: {stats['non_critical_recoverable_failures']}"
        )
        self.logger.info(
            f"  非Critical不可恢复失败: {stats['non_critical_unrecoverable_failures']}"
        )
        self.logger.info(f"  成功率: {success_rate:.2f}%")

    def _print_final_report(self, start_timestamp):
        """打印最终测试报告"""
        total_duration = time.time() - start_timestamp

        self.logger.info("\n" + "=" * 80)
        self.logger.info("500次循环S4测试 - 最终报告")
        self.logger.info("=" * 80)
        self.logger.info(f"测试主机数量: {len(self.hostnames)}")
        self.logger.info(f"测试主机: {self.hostnames}")
        self.logger.info(f"开始时间: {self.global_stats['start_time']}")
        self.logger.info(f"结束时间: {self.global_stats['end_time']}")
        self.logger.info(
            f"总耗时: {total_duration:.2f} 秒 ({total_duration/3600:.2f} 小时)"
        )
        self.logger.info(f"计划循环次数: {self.total_cycles}")

        # 汇总所有主机的统计
        total_success = sum(s["success"] for s in self.stats.values())
        total_failed = sum(s["failed"] for s in self.stats.values())
        total_critical = sum(s["critical_failures"] for s in self.stats.values())
        total_recoverable = sum(
            s["non_critical_recoverable_failures"] for s in self.stats.values()
        )
        total_unrecoverable = sum(
            s["non_critical_unrecoverable_failures"] for s in self.stats.values()
        )
        total_cycles = sum(s["total"] for s in self.stats.values())

        self.logger.info(f"\n汇总统计:")
        self.logger.info(f"  实际完成次数: {total_cycles}")
        self.logger.info(f"  成功次数: {total_success}")
        self.logger.info(f"  失败次数: {total_failed}")
        self.logger.info(f"  Critical失败: {total_critical}")
        self.logger.info(f"  非Critical可恢复失败: {total_recoverable}")
        self.logger.info(f"  非Critical不可恢复失败: {total_unrecoverable}")

        # 每台主机的详细统计
        for hostname in self.hostnames:
            stats = self.stats[hostname]
            success_rate = (
                (stats["success"] / stats["total"] * 100) if stats["total"] > 0 else 0
            )
            self.logger.info(f"\n{hostname} 详细统计:")
            self.logger.info(f"  完成次数: {stats['total']}")
            self.logger.info(f"  成功: {stats['success']}")
            self.logger.info(f"  失败: {stats['failed']}")
            self.logger.info(f"  Critical失败: {stats['critical_failures']}")
            self.logger.info(
                f"  非Critical可恢复失败: {stats['non_critical_recoverable_failures']}"
            )
            self.logger.info(
                f"  非Critical不可恢复失败: {stats['non_critical_unrecoverable_failures']}"
            )
            self.logger.info(f"  成功率: {success_rate:.2f}%")

            if stats["failures"]:
                self.logger.info(f"  失败详情:")
                for failure in stats["failures"]:
                    failure_type_desc = {
                        FailureType.CRITICAL: "CRITICAL",
                        FailureType.NON_CRITICAL_RECOVERABLE: "Non-Critical(可恢复)",
                        FailureType.NON_CRITICAL_UNRECOVERABLE: "Non-Critical(不可恢复)",
                    }.get(failure.failure_type, failure.failure_type.value)

                    self.logger.error(
                        f"    第 {failure.cycle} 次S4失败 [{failure_type_desc}]: {failure.error}"
                    )
                    self.logger.error(
                        f"      失败时间: {failure.timestamp}, 耗时: {failure.duration:.2f}秒"
                    )

        self.logger.info("=" * 80)

        # 判断测试结果
        # 规则：允许有1次非Critical且S4可恢复的Fail，不允许有Critical及S4无法恢复的Fail
        if total_critical > 0:
            self.logger.error(
                f"✗ 测试失败：检测到 {total_critical} 个Critical失败（不允许）"
            )
            return False

        if total_unrecoverable > 0:
            self.logger.error(
                f"✗ 测试失败：检测到 {total_unrecoverable} 个不可恢复的失败（不允许）"
            )
            return False

        if total_recoverable > 1:
            self.logger.error(
                f"✗ 测试失败：检测到 {total_recoverable} 个可恢复的失败（最多允许1个）"
            )
            return False

        if total_recoverable == 1:
            self.logger.warning(
                f"⚠ 测试通过：检测到1个可恢复的失败（符合规则，允许1次）"
            )
            return True

        self.logger.info("✓ 测试通过：所有S4均成功，无任何失败")
        return True

    def _generate_reports(self):
        """生成测试报告（HTML和Excel）"""
        try:
            from utils.report_generator import ReportGenerator

            generator = ReportGenerator(
                self.stats,
                self.global_stats,
                self.hostnames,
                self.total_cycles,
                test_type="s4",
            )
            generator.generate_html_report()
            generator.generate_excel_report()
            self.logger.info("测试报告已生成")
        except ImportError as e:
            self.logger.warning(f"报告生成模块未找到，跳过报告生成: {str(e)}")
        except Exception as e:
            self.logger.error(f"生成报告时出错: {str(e)}", exc_info=True)


# ============================================================================
# pytest测试用例
# ============================================================================

try:
    import pytest
except ImportError:
    # 如果没有安装pytest，跳过pytest测试用例的注册
    pytest = None


if pytest is not None:

    @pytest.mark.s4
    @pytest.mark.slow
    @pytest.mark.integration
    def test_s4_cycles(config_path, required_hosts):
        """
        循环S4测试用例

        测试规则：
        - 使用配置文件中指定的循环次数（从config/account.yaml读取total_cycles）
        - 允许有1次非Critical且S4可恢复的Fail（包括蓝屏、黑屏、系统Hang住等）
        - 不允许有Critical及S4无法恢复的Fail

        Args:
            config_path: 配置文件路径（从conftest.py的fixture获取）
            required_hosts: 需要的机器数量（None表示使用配置中的所有主机）
        """
        # total_cycles=None 表示从配置文件读取
        test = S4CycleTest(
            config_path=config_path,
            total_cycles=None,  # None表示从配置文件读取
            required_hosts=required_hosts,
        )
        success = test.run_test()
        assert success, "测试失败：不符合测试规则要求"
