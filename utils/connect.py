import yaml
import paramiko
import logging

# 配置paramiko日志级别，避免打印详细的连接错误堆栈
paramiko_logger = logging.getLogger("paramiko")
paramiko_logger.setLevel(logging.CRITICAL)  # 设置为CRITICAL以抑制所有日志输出
# 移除paramiko的handler，避免输出到控制台
for handler in paramiko_logger.handlers[:]:
    paramiko_logger.removeHandler(handler)


def load_config(path="config/account.yaml"):
    with open(path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def connect(host, user, password):
    """
    连接到SSH服务器

    Args:
        host: 主机地址
        user: 用户名
        password: 密码（用于密码认证或私钥密码）

    Returns:
        paramiko.SSHClient: SSH客户端连接对象
    """
    import os

    key_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "config", "id_rsa"
    )
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # 先尝试使用私钥连接（如果私钥文件存在）
    if os.path.exists(key_path):
        try:
            # 尝试使用私钥连接（私钥可能没有密码）
            ssh.connect(hostname=host, username=user, key_filename=key_path, timeout=10)
            print(f"使用私钥连接到主机: {host}")
            return ssh
        except paramiko.ssh_exception.PasswordRequiredException:
            # 私钥需要密码，使用提供的password作为私钥密码
            try:
                ssh.connect(
                    hostname=host,
                    username=user,
                    key_filename=key_path,
                    passphrase=password,
                    timeout=10,
                )
                return ssh
            except Exception:
                # 私钥认证失败，继续尝试密码认证
                pass
        except Exception:
            # 私钥认证失败，继续尝试密码认证
            pass

    # 使用密码认证（作为备选方案）
    ssh.connect(hostname=host, username=user, password=password, timeout=10)
    print(f"使用密码认证连接到主机: {host}")
    return ssh


def disconnect(ssh):
    ssh.close()


def command_execute(ssh, command):
    _, stdout, _ = ssh.exec_command(command)
    return stdout.read().decode("utf-8")


if __name__ == "__main__":
    import json

    config = load_config()
    if config is None:
        raise ValueError("加载配置文件失败或配置文件为空")
    if not isinstance(config, dict):
        raise ValueError(f"配置文件必须为字典, 实际类型为: {type(config)}")

    # 解析hosts配置
    hosts_config = config.get("hosts", {})
    if isinstance(hosts_config, str):
        hosts_config = json.loads(hosts_config)

    # 获取第一个主机进行测试
    if not hosts_config:
        raise ValueError("配置中没有主机")

    hostname = list(hosts_config.keys())[0]
    host = hosts_config[hostname]
    user = config.get("user")
    password = config.get("password")

    print(f"测试连接到主机: {hostname} ({host})")
    ssh = connect(host, user, password)
    result = command_execute(ssh, "ls -l")
    print(result)
    disconnect(ssh)
