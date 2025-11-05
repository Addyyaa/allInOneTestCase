import logging
import os
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from threading import Lock


class Logger:
    """
    单例模式的日志工具类
    确保全局只有一个日志实例
    """

    _instance = None
    _lock = Lock()
    _logger = None

    def __new__(cls):
        """单例模式实现"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(Logger, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        """初始化日志配置（只会执行一次）"""
        if self._logger is None:
            self._setup_logger()

    def _setup_logger(self):
        """配置日志"""
        # 创建日志目录
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # 创建logger
        self._logger = logging.getLogger("app_logger")
        self._logger.setLevel(logging.DEBUG)

        # 避免重复添加handler
        if self._logger.handlers:
            return

        # 创建formatter
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # 文件handler - 按日期轮转，每天一个日志文件
        log_file = os.path.join(log_dir, "app.log")
        file_handler = TimedRotatingFileHandler(
            filename=log_file,
            when="midnight",  # 每天午夜轮转
            interval=1,  # 间隔1天
            backupCount=30,  # 保留30天的日志
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

        # 同时添加按大小轮转的handler作为备份（防止单日日志过大）
        size_file_handler = RotatingFileHandler(
            filename=os.path.join(log_dir, "app_size.log"),
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding="utf-8",
        )
        size_file_handler.setLevel(logging.DEBUG)
        size_file_handler.setFormatter(formatter)

        # 控制台handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)

        # 添加handlers
        self._logger.addHandler(file_handler)
        self._logger.addHandler(size_file_handler)
        self._logger.addHandler(console_handler)

    def get_logger(self):
        """获取logger实例"""
        return self._logger

    # 便捷方法
    def debug(self, message):
        """记录DEBUG级别日志"""
        self._logger.debug(message)

    def info(self, message):
        """记录INFO级别日志"""
        self._logger.info(message)

    def warning(self, message):
        """记录WARNING级别日志"""
        self._logger.warning(message)

    def error(self, message):
        """记录ERROR级别日志"""
        self._logger.error(message)

    def critical(self, message):
        """记录CRITICAL级别日志"""
        self._logger.critical(message)


# 全局单例实例
_logger_instance = None
_logger_lock = Lock()


def get_logger():
    """
    获取全局唯一的日志实例

    使用示例:
        from utils.logger import get_logger

        logger = get_logger()
        logger.info("这是一条信息日志")
        logger.error("这是一条错误日志")
    """
    global _logger_instance
    if _logger_instance is None:
        with _logger_lock:
            if _logger_instance is None:
                _logger_instance = Logger()
    return _logger_instance.get_logger()


# 提供便捷的全局函数
def debug(message):
    """DEBUG级别日志"""
    get_logger().debug(message)


def info(message):
    """INFO级别日志"""
    get_logger().info(message)


def warning(message):
    """WARNING级别日志"""
    get_logger().warning(message)


def error(message):
    """ERROR级别日志"""
    get_logger().error(message)


def critical(message):
    """CRITICAL级别日志"""
    get_logger().critical(message)


if __name__ == "__main__":
    logger = get_logger()
    logger.info("这是一条信息日志")
    logger.error("这是一条错误日志")
