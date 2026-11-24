#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 动态获取当前插件所在目录，杜绝写死绝对路径
pluginPath=$(cd $(dirname $0); pwd)

Install_ssh_log()
{
    echo "===================================================="
    echo "正在安装 SSH登录日志 插件..."
    chmod -R 755 $pluginPath
    if [ ! -f "$pluginPath/ip_cache.json" ]; then
        echo "{}" > $pluginPath/ip_cache.json
        chmod 666 $pluginPath/ip_cache.json
    fi
    echo "SSH登录日志 插件安装完成"
    echo "Successify"
}

Uninstall_ssh_log()
{
    echo "===================================================="
    echo "正在卸载 SSH登录日志 插件..."
    rm -rf $pluginPath
    echo "SSH登录日志 插件卸载完成"
    echo "Successify"
}

action=$1
if [ "$action" == "install" ]; then
    Install_ssh_log
elif [ "$action" == "uninstall" ]; then
    Uninstall_ssh_log
fi
