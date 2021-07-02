# auto-submit(Deprecated)

改仓库已停止维护，仅作留恋。
原仓库参见[auto-submit项目](https://github.com/ZimoLoveShuang/auto-submit)

# 快速上手

如果你只使用而不想关注细节，可按照如下步骤直接部署：

1. 下载dist/index（linux版）
2. 拷贝并修改config.yml到某个目录
3. 运行`./index /your/path/config.yml 0`
   * `/your/path/config.yml`: 是修改后的config.yml保存位置
   * `0`: 代表关闭测试模式，设为`1`，则列出填好后的表单，不提交
   
4. \[option\]添加命令到linux触发器`crontab -e`，每日09、12、18点30分各尝试提交一次

```shell
30 09,12,18 * * * /home/xxx/index /home/xxx/config.yml 0 >> /home/xxx/daliysubmit.log 2>&1
```

# 项目说明

- `config.yml` 默认配置文件
- `index.py` 完成自动提交的py脚本（已被打包为dist/index）
- `generate.py` 帮助生成默认项配置的py脚本
- `requirements.txt` python依赖库以及版本说明文件
- `required_selected.json` 执行`index.py`时爬去必填的表单，并以json保存到本地，可删除


