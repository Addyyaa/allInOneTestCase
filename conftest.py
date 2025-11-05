"""
pytest配置文件
提供全局的fixture和配置
"""

import os
import sys
import pytest
import yaml

# 添加项目根目录到路径
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


@pytest.fixture(scope="session")
def config_path():
    """配置文件路径fixture"""
    return "config/account.yaml"


@pytest.fixture(scope="session")
def required_hosts():
    """需要的机器数量fixture"""
    return None  # None表示使用配置中的所有主机
