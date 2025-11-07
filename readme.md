## 前置步骤

1. 将一体机设置为开机免登录
2. 在BIOS的SETUP中， 打开 `RTC ALERT AWAKE`
3. 将`./config/account.yaml`中的配置根据实际需求修改
4. 将`./config/id_rsa.pub`文件写入到测试机`~/.ssh/authorized_keys`

## 测试

1. 右键打开控制台
2. 输入指令`pytest`
3. 运行日志可以在`logs`目录下看到
4. 报告可以在`reports`下看到