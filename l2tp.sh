#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#=======================================================================#
#   System Supported:  CentOS 6+ / Debian 7+ / Ubuntu 12+               #
#   Description: L2TP VPN Auto Installer                                #
#   Author: Merciless                                                   #
#   Intro:  www.merciless.cn                                            #
#=======================================================================#
cur_dir=`pwd`

libreswan_filename="libreswan-3.27"
download_root_url="https://dl.lamp.sh/files"

# 默认配置
DEFAULT_IPRANGE="192.168.18"
DEFAULT_PSK="yaoyao686"
DEFAULT_USERNAME="yaoyao686"
DEFAULT_PASSWORD="yaoyao686"

rootness(){
    if [[ $EUID -ne 0 ]]; then
       echo "Error:This script must be run as root!" 1>&2
       exit 1
    fi
}

tunavailable(){
    if [[ ! -e /dev/net/tun ]]; then
        echo "Error:TUN/TAP is not available!" 1>&2
        exit 1
    fi
}

disable_selinux(){
if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
fi
}

get_opsy(){
    [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
    [ -f /etc/os-release ]     && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
    [ -f /etc/lsb-release ]    && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

get_os_info(){
    IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
         | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." \
         | head -n 1 )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )

    # 获取默认网络接口
    DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    [ -z "$DEFAULT_IFACE" ] && DEFAULT_IFACE="eth0"

    local cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
    local cores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
    local freq=$( awk -F: '/cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
    local tram=$( free -m | awk '/Mem/ {print $2}' )
    local swap=$( free -m | awk '/Swap/ {print $2}' )
    local up=$( awk '{a=$1/86400;b=($1%86400)/3600;c=($1%3600)/60;d=$1%60} {printf("%ddays, %d:%d:%d\n",a,b,c,d)}' /proc/uptime )
    local load=$( w | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//' )
    local opsy=$( get_opsy )
    local arch=$( uname -m )
    local lbit=$( getconf LONG_BIT )
    local host=$( hostname )
    local kern=$( uname -r )

    echo "########## System Information ##########"
    echo 
    echo "CPU model            : ${cname}"
    echo "Number of cores      : ${cores}"
    echo "CPU frequency        : ${freq} MHz"
    echo "Total amount of ram  : ${tram} MB"
    echo "Total amount of swap : ${swap} MB"
    echo "System uptime        : ${up}"
    echo "Load average         : ${load}"
    echo "OS                   : ${opsy}"
    echo "Arch                 : ${arch} (${lbit} Bit)"
    echo "Kernel               : ${kern}"
    echo "Hostname             : ${host}"
    echo "IPv4 address         : ${IP}"
    echo "Default interface    : ${DEFAULT_IFACE}"
    echo 
    echo "########################################"
}

check_sys(){
    local checkType=$1
    local value=$2

    local release='' systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"; systemPackage="yum"
    elif grep -Eqi "debian" /etc/issue; then
        release="debian"; systemPackage="apt"
    elif grep -Eqi "ubuntu" /etc/issue; then
        release="ubuntu"; systemPackage="apt"
    fi

    if [[ ${checkType} == "sysRelease" ]]; then
        [[ "$value" == "$release" ]]
    else
        [[ "$value" == "$systemPackage" ]]
    fi
}

download_file() {
    local filename=$1
    if [ -s ${filename} ]; then
        echo "${filename} [found]"
    else
        echo "Error: ${filename} not found!!!download now..."
        wget -c --no-check-certificate ${download_root_url}/${filename}
        if [ $? -eq 0 ]; then
            echo "Download ${filename} successfully!"
        else
            echo "Error: Download ${filename} failed!"
            exit 1
        fi
    fi
}

rand(){
    index=0; str=""
    for i in {a..z} {A..Z} {0..9}; do
        arr[index]=${i}; index=$((index+1))
    done
    for i in {1..10}; do
        str+="${arr[$RANDOM%$index]}"
    done
    echo ${str}
}

preinstall_l2tp(){
    echo "使用默认配置安装 L2TP/IPsec VPN..."
    echo "IP 范围前缀: ${DEFAULT_IPRANGE}"
    echo "预共享密钥: ${DEFAULT_PSK}"
    echo "用户名: ${DEFAULT_USERNAME}"
    echo "密码: ${DEFAULT_PASSWORD}"
    
    if [[ -d "/proc/vz" ]]; then
        echo -e "\033[41;37m WARNING: \033[0m Your VPS is OpenVZ; IPSec might not work."
        echo "正在继续安装..."
    fi
    
    iprange="${DEFAULT_IPRANGE}"
    mypsk="${DEFAULT_PSK}"
    username="${DEFAULT_USERNAME}"
    password="${DEFAULT_PASSWORD}"

    echo
    echo "ServerIP: ${IP}"
    echo "Local IP: ${iprange}.1"
    echo "Client IP Range: ${iprange}.2-${iprange}.254"
    echo "PSK: ${mypsk}"
    echo "正在开始安装，请稍候..."
    sleep 2
}

install_l2tp(){
    disable_selinux
    
    # 安装必要的软件包
    echo "正在安装必要的软件包..."
    if check_sys packageManager yum; then
        yum -y install epel-release ppp libreswan xl2tpd firewalld > /dev/null 2>&1
    else
        apt-get -y update > /dev/null 2>&1
        
        # 安装必要的依赖
        apt-get -y install ppp xl2tpd libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
            libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison \
            gcc make libldns-dev libunbound-dev libnss3-tools libevent-dev > /dev/null 2>&1
            
        # 对于Ubuntu系统，使用官方版本的libreswan
        if check_sys sysRelease ubuntu; then
            apt-get -y install libreswan > /dev/null 2>&1
        else
            # 对于Debian系统，可能需要编译安装
            echo "正在下载并编译 libreswan..."
            download_file "${libreswan_filename}.tar.gz"
            tar -zxf ${libreswan_filename}.tar.gz
            cd ${libreswan_filename}
            cat > Makefile.inc.local <<'EOF'
WERROR_CFLAGS =
USE_DNSSEC = false
USE_DH31 = false
USE_GLIBC_KERN_FLIP_HEADERS = true
EOF
            make programs > /dev/null 2>&1 && make install > /dev/null 2>&1
            cd "${cur_dir}"
        fi
    fi

    # 配置IPSec
    echo "正在配置IPSec..."
    cat > /etc/ipsec.conf <<EOF
config setup
    protostack=netkey
    uniqueids=no
    nat_traversal=yes
    virtual_private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12

conn L2TP-PSK
    authby=secret
    pfs=no
    auto=add
    rekey=no
    type=transport
    ike=aes256-sha2_256;modp2048,aes128-sha1;modp2048,aes128-sha1;modp1536,aes128-sha1;modp1024
    phase2alg=aes256-sha2_256,aes128-sha1,3des-sha1
    left=%defaultroute
    leftid=${IP}
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    forceencaps=yes
EOF

    cat > /etc/ipsec.secrets <<EOF
%any %any : PSK "${mypsk}"
EOF

    # 配置XL2TPD
    echo "正在配置XL2TPD..."
    cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
ipsec saref = yes

[lns default]
ip range = ${iprange}.2-${iprange}.254
local ip = ${iprange}.1
require chap = yes
refuse pap = yes
require authentication = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

    cat > /etc/ppp/options.xl2tpd <<EOF
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
asyncmap 0
auth
crtscts
lock
hide-password
modem
debug
name l2tpd
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
EOF

    cat > /etc/ppp/chap-secrets <<EOF
${username}    l2tpd    ${password}    *
EOF

    # 启用IP转发
    echo "正在启用IP转发..."
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    sysctl -p > /dev/null 2>&1

    # 配置防火墙
    echo "正在配置防火墙..."
    if check_sys sysRelease ubuntu; then
        # Ubuntu使用UFW防火墙
        ufw disable
        
        # 添加必要的防火墙规则
        ufw allow 500/udp > /dev/null 2>&1
        ufw allow 4500/udp > /dev/null 2>&1
        ufw allow 1701/udp > /dev/null 2>&1
        ufw allow proto ah > /dev/null 2>&1
        ufw allow proto esp > /dev/null 2>&1
        
        # 启用IP转发
        sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/ufw/sysctl.conf
        
        # 添加NAT规则
        cat > /etc/ufw/before.rules <<EOF
#
# rules.before
#
# Rules that should be run before the ufw command line added rules. Custom
# rules should be added to one of these chains:
#   ufw-before-input
#   ufw-before-output
#   ufw-before-forward
#

# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]

# Allow NAT for VPN clients
-A POSTROUTING -s ${iprange}.0/24 -o ${DEFAULT_IFACE} -j MASQUERADE

# don't delete the 'COMMIT' line or these nat table rules won't be processed
COMMIT

# Don't delete these required lines, otherwise there will be errors
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
:ufw-not-local - [0:0]
# End required lines

# allow all on loopback
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT

# quickly process packets for which we already have a connection
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# drop INVALID packets (logs these in loglevel medium and higher)
-A ufw-before-input -m conntrack --ctstate INVALID -j ufw-logging-deny
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP

# ok icmp codes for INPUT
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT

# ok icmp codes for FORWARD
-A ufw-before-forward -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type echo-request -j ACCEPT

# allow dhcp client to work
-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT

#
# ufw-not-local
#
-A ufw-before-input -j ufw-not-local

# if LOCAL, RETURN
-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN

# if MULTICAST, RETURN
-A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN

# if BROADCAST, RETURN
-A ufw-not-local -m addrtype --dst-type BROADCAST -j RETURN

# all other non-local packets are dropped
-A ufw-not-local -m limit --limit 3/min --limit-burst 10 -j ufw-logging-deny
-A ufw-not-local -j DROP

# allow MULTICAST mDNS for service discovery (be sure the MULTICAST line above
# is uncommented)
-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT

# allow MULTICAST UPnP for service discovery (be sure the MULTICAST line above
# is uncommented)
-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT

# don't delete the 'COMMIT' line or these rules won't be processed
COMMIT
EOF
        
        # 设置默认转发策略
        sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/g' /etc/default/ufw
        
        # 重新启用UFW
        echo "y" | ufw enable > /dev/null 2>&1
    else
        # CentOS使用firewalld
        systemctl enable --now firewalld > /dev/null 2>&1
        firewall-cmd --permanent --add-service=ipsec > /dev/null 2>&1
        firewall-cmd --permanent --add-port=1701/udp > /dev/null 2>&1
        firewall-cmd --permanent --add-port=4500/udp > /dev/null 2>&1
        firewall-cmd --permanent --add-port=500/udp > /dev/null 2>&1
        firewall-cmd --permanent --add-masquerade > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
    fi

    # 设置NAT规则
    echo "正在设置NAT规则..."
    iptables -t nat -A POSTROUTING -s ${iprange}.0/24 -o ${DEFAULT_IFACE} -j MASQUERADE
    
    # 确保转发规则在重启后仍然有效
    if check_sys sysRelease ubuntu; then
        # 创建持久化脚本
        cat > /etc/network/if-pre-up.d/iptables <<EOF
#!/bin/sh
iptables -t nat -A POSTROUTING -s ${iprange}.0/24 -o ${DEFAULT_IFACE} -j MASQUERADE
exit 0
EOF
        chmod +x /etc/network/if-pre-up.d/iptables
    else
        # CentOS使用firewalld，规则已经持久化
        echo "Firewall rules are already persistent on CentOS"
    fi

    # 启动服务
    echo "正在启动服务..."
    if check_sys sysRelease ubuntu; then
        # 对于Ubuntu，确保使用正确的服务名称
        systemctl enable ipsec > /dev/null 2>&1
        systemctl enable xl2tpd > /dev/null 2>&1
        systemctl restart ipsec > /dev/null 2>&1
        systemctl restart xl2tpd > /dev/null 2>&1
    else
        systemctl enable --now ipsec > /dev/null 2>&1
        systemctl enable --now xl2tpd > /dev/null 2>&1
    fi
    
    # 等待服务启动
    sleep 3
    
    echo "✅ 安装完成！"
}

finally(){
    clear
    echo "✅ L2TP/IPsec VPN 安装完成！"
    echo "服务器 IP        : ${IP}"
    echo "预共享密钥       : ${mypsk}"
    echo "VPN 用户名       : ${username}"
    echo "VPN 密码         : ${password}"
    echo "本地地址         : ${iprange}.1"
    echo "客户端分配范围   : ${iprange}.2-${iprange}.254"
    echo "连接类型         : L2TP/IPSec PSK"
    echo "默认网络接口     : ${DEFAULT_IFACE}"
    echo
    echo "QQ群："
    echo "TG群："
    echo
}

# Main
echo "开始自动安装 L2TP/IPsec VPN..."
echo "使用默认配置："
echo "- IP范围: ${DEFAULT_IPRANGE}.0/24"
echo "- 预共享密钥: ${DEFAULT_PSK}"
echo "- 用户名: ${DEFAULT_USERNAME}"
echo "- 密码: ${DEFAULT_PASSWORD}"
echo
rootness
tunavailable
get_os_info
preinstall_l2tp
install_l2tp
finally
