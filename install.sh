#!/bin/bash

getAptPackage(){
    printf "\n\n==> Getting environment packages\n"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update && apt-get install -y vim ntp zip unzip curl wget build-essential fp-compiler python2.7 python3.8 python3-requests
}

setJudgeConf(){
    printf "\n\n==> Setting judger files\n"
    #specify environment
    cat > /etc/environment <<UOJEOF
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
UOJEOF
    #Add judger user
    adduser judger --gecos "" --disabled-password
    #Set uoj_data path
    mkdir /var/uoj_data_copy && chown judger /var/uoj_data_copy
    #Compile uoj_judger and set runtime
    chown -R judger:judger /opt/uoj_judger
    su judger <<EOD
ln -s /var/uoj_data_copy /opt/uoj_judger/uoj_judger/data
cd /opt/uoj_judger && chmod +x judge_client
cat >uoj_judger/include/uoj_work_path.h <<UOJEOF
#define UOJ_WORK_PATH "/opt/uoj_judger/uoj_judger"
#define UOJ_JUDGER_BASESYSTEM_UBUNTU1804
#define UOJ_JUDGER_PYTHON3_VERSION "3.8"
#define UOJ_JUDGER_FPC_VERSION "3.0.4"
UOJEOF
cd uoj_judger && make -j$(($(nproc) + 1))
EOD
}

initProgress(){
    printf "\n\n==> Doing initial config and start service\n"
    # Check envs
    if [ -z "$UOJ_PROTOCOL" -o -z "$UOJ_HOST" -o -z "$JUDGER_NAME" -o -z "$JUDGER_PASSWORD" -o -z "$SOCKET_PORT" -o -z "$SOCKET_PASSWORD" ]; then
        echo "!! Environment variables not set! Please edit config file by yourself!"
    else
        # Set judge_client config file
        cat >.conf.json <<UOJEOF
{
    "uoj_protocol": "$UOJ_PROTOCOL",
    "uoj_host": "$UOJ_HOST",
    "judger_name": "$JUDGER_NAME",
    "judger_password": "$JUDGER_PASSWORD",
    "socket_port": $SOCKET_PORT,
    "socket_password": "$SOCKET_PASSWORD"
}
UOJEOF
        chmod 600 .conf.json && chown judger .conf.json
        chown -R judger:judger ./log
        #Start services
        service ntp restart
        su judger -c '/opt/uoj_judger/judge_client start'
        echo "please modify the database after getting the judger server ready:"
        echo "insert into judger_info (judger_name, password, ip) values ('$JUDGER_NAME', '$JUDGER_PASSWORD', '__judger_ip_here__');"
        printf "\n\n***Installation complete. Enjoy!***\n"
    fi
}

prepProgress(){
    setJudgeConf
}

dockerPrep(){
	echo "#!/bin/sh
mkdir -p /opt/uoj_judger/log /opt/uoj_judger/uoj_judger/result
touch /opt/uoj_judger/log/judge.log
chown -R judger:judger /opt/uoj_judger/log /opt/uoj_judger/uoj_judger/result

# 挂载 cgroup2 文件系统（使用 cgroup namespace 隔离）
# 容器使用 cgroup: private，所以看到的是自己的 cgroup 子树
# Docker 可能已经挂载了只读的 cgroup，需要重新挂载为可写
if [ -d /sys/fs/cgroup ]; then
  # 先尝试 umount 再重新 mount（需要 SYS_ADMIN）
  umount /sys/fs/cgroup 2>/dev/null || true
  mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null || true
fi

if [ ! -f \"/opt/uoj_judger/.conf.json\" ]; then
  cd /opt/uoj_judger && sh install.sh -i
fi
# Fix data symlink (may be overwritten by volume mount)
rm -rf /opt/uoj_judger/uoj_judger/data
ln -sf /var/uoj_data_copy /opt/uoj_judger/uoj_judger/data
chown -h judger:judger /opt/uoj_judger/uoj_judger/data
# Recompile binaries to ensure compatibility with Docker environment
cd /opt/uoj_judger/uoj_judger && make clean >/dev/null 2>&1 && make -j\$(nproc) all checker >/dev/null 2>&1
chown -R judger:judger /opt/uoj_judger/uoj_judger
service ntp start
cd /opt/uoj_judger
exec su judger -c '/opt/uoj_judger/judge_client'" >/opt/up
    chmod +x /opt/up
}

if [ $# -le 0 ]; then
    echo 'Installing UOJ System judger...'
    prepProgress;initProgress
fi
while [ $# -gt 0 ]; do
    case "$1" in
        -p | --prep)
            echo 'Preparing UOJ System judger environment...'
            prepProgress
        ;;
        -d | --docker)
            echo '[Docker] Preparing UOJ System judger environment...'
            dockerPrep
        ;;
        -i | --init)
            echo 'Initing UOJ System judger...'
            initProgress
        ;;
        -? | --*)
            echo "Illegal option $1"
        ;;
    esac
    shift $(( $#>0?1:0 ))
done
