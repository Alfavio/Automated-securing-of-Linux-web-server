#!/bin/bash
#===============================================================================
#
#          FILE:  script.sh
#
#         USAGE:  chmod a+x script.sh && ./script.sh
#
#   DESCRIPTION:  This is a hardening script to configure and harden Linux
#                 Ubuntu Servers after a clean installation. It installs and
#                 configures OpenSSH, Apache 2.4, MariaDB 10.3 and PHP 7.2. It
#                 also configures Linux, specifically the firewall, passwords,
#                 filesystem, network protocols, kernel, permissions,
#                 uninstalls unnecessary packages and installs and configures
#                 recommended security programs.
#
#  REQUIREMENTS:  1. Clean installation of the Ubuntu Server 16.04.4 64-bit
#                    (also works on the Ubuntu Server 18.04.2 64-bit, other
#                    Ubuntu versions are not tested).
#                 2. You are logged in as a user with the root privileges
#                    (not root user, because you will not be able to log in
#                    via the SSH. PermitRootLogin will be disabled).
#                 3. Stable internet connection.
#                 4. Execution permission for this file.
#
#        AUTHOR:  Michal Olenčin, michal@olencin.com
#
#       VERSION:  1.0
#===============================================================================

#===  VARIABLES  ===============================================================
#   DESCRIPTION: Variables defining text decorations for the echo command
#                (e. g. bold text).
#===============================================================================
DECORATION_DIM_OFF="\e[22m"
DECORATION_DIM_ON="\e[2m"

#===  VARIABLES  ===============================================================
#   DESCRIPTION: Variables defining text color for the echo command.
#===============================================================================
COLOR_244="\e[38;5;244m"
COLOR_245="\e[38;5;245m"
COLOR_246="\e[38;5;246m"
COLOR_247="\e[38;5;247m"
COLOR_248="\e[38;5;248m"
COLOR_249="\e[38;5;249m"
COLOR_250="\e[38;5;250m"
COLOR_251="\e[38;5;251m"
COLOR_252="\e[38;5;252m"
COLOR_253="\e[38;5;253m"
COLOR_254="\e[38;5;254m"
COLOR_255="\e[38;5;255m"
COLOR_256="\e[38;5;256m"
COLOR_DEFAULT="\e[39m"
COLOR_GREEN="\e[32m"
COLOR_RED="\e[91m"

#===  VARIABLES  ===============================================================
#   DESCRIPTION: Variables defining paths to files or directories.
#===============================================================================
APACHE_CONF="/etc/apache2/apache2.conf"
APACHE_DIR="/etc/apache2"
APACHE_DIR_LIB="/usr/lib/apache2"
APACHE_DIR_LOG="/var/log/apache2"
APACHE_DIR_SBIN="/usr/sbin/apache2"
APACHE_DIR_SHARE="/usr/share/apache2"
APACHE_ENVVARS="/etc/apache2/envvars"
APACHE_EVASIVE_CONF="/etc/apache2/mods-enabled/evasive.conf"
APACHE_SECURITY_CONF="/etc/apache2/conf-enabled/security.conf"
APACHE_MOD_SECURITY_CONF="/etc/modsecurity/modsecurity.conf"
APACHE_WEB_ROOT="/var/www/html"
APT_LIST="/var/lib/apt/lists"
APT_PERIODIC_CONF="/etc/apt/apt.conf.d/10periodic"
APT_TIMER="/lib/systemd/system/apt-daily.timer"
AUDITD_CONF="/etc/audit/auditd.conf"
AUDITD_LOG="/var/log/audit/audit.log"
AUDITD_RULES="/etc/audit/audit.rules"
AVAHI_DIR="/var/run/avahi-daemon"
BASHRC="/etc/bash.bashrc"
CRON_CRONTAB="/etc/crontab"
CRON_D="/etc/cron.d"
CRON_DAILY="/etc/cron.daily"
CRON_DENY="/etc/cron.deny"
CRON_HOURLY="/etc/cron.hourly"
CRON_MONTHLY="/etc/cron.monthly"
CRON_WEEKLY="/etc/cron.weekly"
CUPS_DIR="/etc/cups"
FSTAB="/etc/fstab"
GROUP="/etc/group"
GROUP_="/etc/group-"
GRUB_CONFIG="/boot/grub/grub.cfg"
GRUB_MENU="/boot/grub/menu.lst"
GSHADOW="/etc/gshadow"
GSHADOW_="/etc/gshadow-"
HLIP_DIR="/usr/share/hplip"
HOSTS_ALLOW="/etc/hosts.allow"
HOSTS_DENY="/etc/hosts.deny"
INIT_RC="/etc/init.d/rc"
ISSUE="/etc/issue"
ISSUE_NET="/etc/issue.net"
LOG_DIRECTORY="/var/log/"
LOGIN_DEFS="/etc/login.defs"
MARIADB_CNF="/etc/mysql/my.cnf"
MODPROBE_CRAMFS="/etc/modprobe.d/cramfs.conf"
MODPROBE_DCCP="/etc/modprobe.d/dccp.conf"
MODPROBE_FREEVXFS="/etc/modprobe.d/freevxfs.conf"
MODPROBE_HFS="/etc/modprobe.d/hfs.conf"
MODPROBE_HFSPLUS="/etc/modprobe.d/hfsplus.conf"
MODPROBE_JFFS2="/etc/modprobe.d/jffs2.conf"
MODPROBE_RDS="/etc/modprobe.d/rds.conf"
MODPROBE_SCTP="/etc/modprobe.d/sctp.conf"
MODPROBE_SQUASHFS="/etc/modprobe.d/squashfs.conf"
MODPROBE_TIPC="/etc/modprobe.d/tipc.conf"
MODPROBE_UDF="/etc/modprobe.d/udf.conf"
MODPROBE_USB="/etc/modprobe.d/usb.conf"
MODPROBE_VFAT="/etc/modprobe.d/vfat.conf"
PASSWD="/etc/passwd"
PASSWD_="/etc/passwd-"
PHP_INI="/etc/php/7.2/cli/php.ini"
PHP_SESSION_DIR="/var/lib/php/session"
PHP_SOAP_CACHE="/var/lib/php/soap_cache"
PROFILE="/etc/profile"
PWQUALITY_CONF="/etc/security/pwquality.conf"
RESOLV_CONF="/etc/resolv.conf"
SECURITY_LIMITS_CONF="/etc/security/limits.conf"
SHADOW="/etc/shadow"
SHADOW_="/etc/shadow-"
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_PAM="/etc/pam.d/sshd"
SYSCTL_CONF="/etc/sysctl.conf"
SYSSTAT="/etc/default/sysstat"
USBGURAD_CONF="/etc/usbguard/usbguard-daemon.conf"

#===  VARIABLES  ===============================================================
#   DESCRIPTION: Variables defining information about the current environments.
#===============================================================================
CURRENT_USER=${SUDO_USER:-$USER}
CURRENT_USER_HOME_DIR=$(eval echo ~"${CURRENT_USER}")
MACHINE_IP=$(dig +short myip.opendns.com @resolver1.opendns.com)

#===  FUNCTION  ================================================================
#          NAME: add_crontab_task
#   DESCRIPTION: Add task to cron.
#     PARAMETER: valid task (e. g. "1 * * * * echo "one minute passed")
#===============================================================================
function add_crontab_task {
    append_to_file "$1" ${CRON_CRONTAB}
}

#===  FUNCTION  ================================================================
#          NAME: append_to_file
#   DESCRIPTION: Append the input to a file, if the file does not contain any input.
#    PARAMETERS: 1. input to append
#                2. file
#===============================================================================
function append_to_file {
    grep -Eq "^$1&" $2
    local EXIT_STATUS=$?
    if [[ ${EXIT_STATUS} -ne 0 ]]; then
        echo -e "$1" >> $2
    fi
}

#===  FUNCTION  ================================================================
#          NAME: backup_file
#   DESCRIPTION: Backup a file.
#     PARAMETER: Path to file.
#===============================================================================
function backup_file {
    cp $1{,.bak}
}

#===  FUNCTION  ================================================================
#          NAME: comment_parameter
#   DESCRIPTION: Comment out a parameter in the configuration file.
#    PARAMETERS: 1. parameter name (escaped special characters)
#                2. configuration file path
#===============================================================================
function comment_parameter {
    sed -i $2 -e "/$1/s/^/#/"
}

#===  FUNCTION  ================================================================
#          NAME: fix_apt_list_lock
#   DESCRIPTION: Fix errors when calling apt: "Could not get lock
#                /var/lib/apt/lists/lock - open (11: Resource temporarily
#                unavailable)"
#     PARAMETER: ---
#===============================================================================
function fix_apt_list_lock {
    rm -rf ${APT_LIST}
}

#===  FUNCTION  ================================================================
#          NAME: get_diff_lines
#   DESCRIPTION: Save the number of different lines in the specified files to the
#                variable "DIFF_LINES"
#    PARAMETERS: 1. file 1 (e. g. "/boot/grub/grub.cfg")
#                2. file 2 (e. g. "/boot/grub/grub.cfg.bak")
#===============================================================================
function get_diff_lines {
    DIFF_LINES=$(diff -y --suppress-common-lines $1 $2 | grep '^' | wc -l)
}

#===  FUNCTION  ================================================================
#          NAME: password_generate
#   DESCRIPTION: Generate a random, 32 letters long password to the variable
#                "PASSWORD_GENERATED". The password contains symbols, numbers,
#                uppercase letters and lowercase letters.
#     PARAMETER: ---
#===============================================================================
function password_generate {
    PASSWORD_GENERATED=$(tr -dc '[:graph:]' < /dev/urandom | head -c ${1:-32}; echo;)
}

#===  FUNCTION  ================================================================
#          NAME: print_info
#   DESCRIPTION: Print the input info text.
#     PARAMETER: Text to print.
#===============================================================================
function print_info {
    echo -e "${DECORATION_BOLD_ON}[SCRIPT]${DECORATION_DIM_OFF} $1"
}

#===  FUNCTION  ================================================================
#          NAME: set_parameter
#   DESCRIPTION: Set the parameters in the configuration file. If the parameter does not exist in
#                the configuration file, add it.
#    PARAMETERS: 1. parameter name (escaped special characters)
#                2. parameter value (escaped special characters)
#                3. configuration path
#                4. OPTIONAL - prefix for value (default is the space)
#===============================================================================
function set_parameter {
    grep -qE "^(#\s)?$1" $3
    local EXIT_STATUS=$?
    if [[ ${EXIT_STATUS} -ne 0 ]]; then
        echo -e "$1${4-" "}$2" >> $3
    else
        sed -i.old -E "/^$1/c\\$1${4-" "}$2" $3
        get_diff_lines $3 $3.old
        grep -qE "^$1${4-" "}$2" $3
        local EXIT_STATUS=$?
        if [[ ${DIFF_LINES} -eq 0 ]] && [[ ${EXIT_STATUS} -ne 0 ]]; then
            sed -i.old -E "/^(#)?$1/c\\$1${4-" "}$2" $3
            get_diff_lines $3 $3.old
            if [[ ${DIFF_LINES} -eq 0 ]]; then
                sed -i.old -E "/^(#\s)?$1/c\\$1${4-" "}$2" $3
            fi
        fi
        rm $3.old
    fi
}

#===  FUNCTION  ================================================================
#          NAME: set_permission
#   DESCRIPTION: Set the ownership and permissions for a file.
#    PARAMETERS: 1. ownership (e. g. "root:root")
#                2. permission (e. g. "0644")
#                3. file (e. g. "/boot/grub/grub.cfg")
#===============================================================================
function set_permission {
    chown $1 $3
    chmod $2 $3
}

#===  FUNCTION  ================================================================
#          NAME: set_permission_recursive
#   DESCRIPTION: Set recursive ownership and permissions for a directory.
#    PARAMETERS: 1. ownership (e. g. "root:root")
#                2. permission (e. g. "0644")
#                3. directory (e. g. "/boot/grub/")
#===============================================================================
function set_permission_recursive {
    chown -R $1 $3
    chmod -R $2 $3
}

#===  FUNCTION  ================================================================
#          NAME: ssh_harden
#   DESCRIPTION: Install and harden ssh server.
#     PARAMETER: ---
#===============================================================================
function ssh_harden {

    print_info "${DECORATION_BOLD_ON}HARDENING SSH${DECORATION_BOLD_OFF}"

    print_info "Installing ssh server."
    apt -y install openssh-server

    print_info "Backing up ssh configuration files."
    backup_file ${SSHD_CONFIG}
    backup_file ${SSHD_PAM}

    # Generate ssh key.
    print_info "Please generete ssh keys with command ${DECORATION_BOLD_ON}\"ssh-keygen -t rsa -b 4096\"${DECORATION_BOLD_OFF} on your local machine and copy the public keys to this machine ${DECORATION_DIM_ON}(ssh-copy-id ${CURRENT_USER}@${MACHINE_IP})${DECORATION_BOLD_OFF}."
    password_generate
    print_info "You can use this autogenerated passphrase:\n${DECORATION_BOLD_ON}$PASSWORD_GENERATED${DECORATION_BOLD_OFF}"
    print_info "When you are done, press any key to continue. \c"
    read -n 1 -s
    echo -e "\n\c"

    print_info "Stopping ssh server."
    systemctl stop ssh

    print_info "Changing ssh port from input."
    print_info "Please enter the port of the ssh server ${DECORATION_DIM_ON}(for default port press enter)${DECORATION_DIM_OFF}:"
    read SSH_PORT
    if [[ ${SSH_PORT} = "" ]]; then
        SSH_PORT="22"
    else
        SSH_PORT=$((10#${SSH_PORT//[!0-9]/}))
    fi
    print_info "Configuring ssh port to ${SSH_PORT}."
    set_parameter "Port" ${SSH_PORT} ${SSHD_CONFIG}

    print_info "Disabling the banner message from motd."
    comment_parameter "^session[ ]*optional[ ]*pam_motd.so[ ]*motd=\/run\/motd.dynamic" ${SSHD_PAM}
    comment_parameter "^session[ ]*optional[ ]*pam_motd.so[ ]*noupdate" ${SSHD_PAM}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.15
    print_info "Configuring the text, that is shown before the authorization when an ssh session is connected."
    backup_file ${ISSUE_NET}
    echo "********************************************************************" > ${ISSUE_NET}
    echo "*                                                                  *" >> ${ISSUE_NET}
    echo "* This system is for the use of authorized users only.  Usage of   *" >> ${ISSUE_NET}
    echo "* this system may be monitored and recorded by system personnel.   *" >> ${ISSUE_NET}
    echo "*                                                                  *" >> ${ISSUE_NET}
    echo "* Anyone using this system expressly consents to such monitoring   *" >> ${ISSUE_NET}
    echo "* and is advised that if such monitoring reveals possible          *" >> ${ISSUE_NET}
    echo "* evidence of criminal activity, system personnel may provide the  *" >> ${ISSUE_NET}
    echo "* evidence from such monitoring to law enforcement officials.      *" >> ${ISSUE_NET}
    echo "*                                                                  *" >> ${ISSUE_NET}
    echo "********************************************************************" >> ${ISSUE_NET}
    set_parameter "Banner" "/etc/issue.net" ${SSHD_CONFIG}

    print_info "Disabling password authentication."
    set_parameter "PasswordAuthentication" "no" ${SSHD_CONFIG}

    print_info "Enabling public key authentication."
    set_parameter "PubkeyAuthentication" "yes" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.7
    print_info "Disabling the authentication of throughtrusted hosts via the user."
    set_parameter "HostbasedAuthentication" "no" ${SSHD_CONFIG}
    set_parameter "RhostsRSAAuthentication" "no" ${SSHD_CONFIG}

    print_info "Disabling challenge-response authentication."
    set_parameter "ChallengeResponseAuthentication" "no" ${SSHD_CONFIG}

    print_info "Disabling GSSAPI authentication."
    set_parameter "GSSAPIAuthentication" "no" ${SSHD_CONFIG}

    print_info "Disabling RSA authentication."
    set_parameter "RSAAuthentication" "no" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.6
    print_info "Disabling .rhosts and .shosts files in RhostsRSAAuthentication or HostbasedAuthentication."
    set_parameter "IgnoreRhosts" "yes" ${SSHD_CONFIG}

    print_info "Disabling the use of DNS in SSH."
    set_parameter "UseDNS" "no" ${SSHD_CONFIG}

    # Lynis recommendation [test:SSH-7408]
    print_info "Disabling TCP forwarding."
    set_parameter "AllowTcpForwarding" "no" ${SSHD_CONFIG}

    # Lynis recommendation [test:SSH-7408]
    print_info "Disabling sending TCP keepalive messages to the other side."
    set_parameter "TCPKeepAlive" "no" ${SSHD_CONFIG}

    # Lynis recommendation [test:SSH-7408]
    print_info "Disabling compression."
    set_parameter "Compression" "no" ${SSHD_CONFIG}

    # Lynis recommendation [test:SSH-7408]
    print_info "Separating privileges by creating an unprivileged child process to deal with incoming network traffic to SANDBOX."
    set_parameter "UsePrivilegeSeparation" "SANDBOX" ${SSHD_CONFIG}

    # Lynis recommendation [test:SSH-7408]
    print_info "Disabling ssh-agent forwarding."
    set_parameter "AllowAgentForwarding" "no" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.2
    print_info "Configuring protocol to version 2."
    set_parameter "Protocol" "2" ${SSHD_CONFIG}

    print_info "Configuring logging levels to verbose."
    set_parameter "LogLevel" "VERBOSE" ${SSHD_CONFIG}

    print_info "Disabling X11 forwarding."
    set_parameter "X11Forwarding" "no" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.5
    # Lynis recommendation [test:SSH-7408]
    print_info "Configuring the maximum number of authentication attempts permitted per connection to 2."
    set_parameter "MaxAuthTries" "2" ${SSHD_CONFIG}

    # Lynis recommendation [test:SSH-7408]
    print_info "Configuring the maximum number of open shell, login or subsystem (e.g. sftp) sessions permitted per network connection to 2."
    set_parameter "MaxSessions" "2" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.8
    print_info "Disabling root logins."
    set_parameter "PermitRootLogin" "no" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.11
    print_info "Configuring ciphers and algorithms."
    set_parameter "KexAlgorithms" "curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" ${SSHD_CONFIG}
    set_parameter "Ciphers" "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" ${SSHD_CONFIG}
    set_parameter "MACs" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" ${SSHD_CONFIG}
    awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.tmp && mv /etc/ssh/moduli.tmp /etc/ssh/moduli

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.12
    print_info "Configuring the idle timeout interval to 300 seconds ${DECORATION_DIM_ON}(5 minutes)${DECORATION_DIM_OFF}."
    set_parameter "ClientAliveInterval" "300" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.13
    print_info "Configuring the time allowed for successful authentication to the SSH server to 60 seconds ${DECORATION_DIM_ON}(1 minute)${DECORATION_DIM_OFF}."
    set_parameter "LoginGraceTime" "60" ${SSHD_CONFIG}

    print_info "Disabling distribution information."
    set_parameter "DebianBanner" "no" ${SSHD_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.2.14
    print_info "Adding current user to ${DECORATION_BOLD_ON}\"ssh\"${DECORATION_BOLD_OFF} group."
    usermod -a -G ssh ${CURRENT_USER}
    print_info "Configuring SSH access only to ${DECORATION_BOLD_ON}\"ssh\"${DECORATION_BOLD_OFF} group."
    set_parameter "AllowGroups" "ssh" ${SSHD_CONFIG}

    print_info "Starting shh service."
    systemctl start ssh

}

#===  FUNCTION  ================================================================
#          NAME: apache_harden
#   DESCRIPTION: Install and harden apache2.
#     PARAMETER: ---
#===============================================================================
function apache_harden {

    print_info "${DECORATION_BOLD_ON}HARDENING APACHE2${DECORATION_BOLD_OFF}"

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 1.3
    print_info "Installing apache web server with necessary module libs."
    apt -y install software-properties-common python-software-properties 
    # Fix issue with non-UTF-8 locales. https://github.com/oerdnj/deb.sury.org/issues/56
    export LC_ALL=C.UTF-8
    add-apt-repository -y ppa:ondrej/apache2
    apt-key update
    fix_apt_list_lock
    apt update
    apt -y install apache2 libapache2-mod-security2 libapache2-mod-evasive

    print_info "Stopping the apache web server service."
    systemctl stop apache2

    print_info "Backing up apache web server configuration files."
    backup_file ${APACHE_CONF}
    backup_file ${APACHE_SECURITY_CONF}
    backup_file ${APACHE_ENVVARS}

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 3.1
    print_info "Running the apache web server as a non-root user ${DECORATION_DIM_ON}(as user apache)${DECORATION_DIM_OFF}."
    groupadd -r apache
    useradd apache -r -g apache -d /var/www -s /sbin/nologin
    set_parameter "export APACHE_RUN_USER=" "apache" ${APACHE_ENVVARS} ""
    set_parameter "export APACHE_RUN_GROUP=" "apache" ${APACHE_ENVVARS} ""

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 3.3
    print_info "Locking the apache user account."
    passwd -l apache

    print_info "Loading apache web server environment."
    source ${APACHE_ENVVARS}

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 2.3
    print_info "Disabling WebDAV modules."
    a2dismod dav
    a2dismod dav_fs

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 2.4
    print_info "Disabling the status module."
    a2dismod status

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 2.5
    print_info "Disabling the autoindex module."
    a2dismod -f autoindex

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 2.6
    print_info "Disabling proxy modules."
    a2dismod proxy
    a2dismod proxy_connect
    a2dismod proxy_ftp
    a2dismod proxy_http
    a2dismod proxy_fcgi
    a2dismod proxy_scgi
    a2dismod proxy_ajp
    a2dismod proxy_balancer
    a2dismod proxy_express
    a2dismod proxy_wstunnel
    a2dismod proxy_fdpass

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 2.7
    print_info "Disabling the user directories module."
    a2dismod userdir

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 2.8
    print_info "Disabling the info module."
    a2dismod info

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 6.6
    print_info "Enabling the security module."
    a2enmod security2

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 7.1
    print_info "Enabling the ssl module."
    a2enmod ssl

    print_info "Enabling the evasive module."
    a2enmod evasive

    print_info "Enabling the headers module."
    a2enmod headers

    print_info "Enabling the include module."
    a2enmod include

    print_info "Enabling the request timeout module."
    a2enmod reqtimeout

    print_info "Enabling the http2 module."
    a2enmod http2

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 3.4  3.5 3.6 3.7 3.8 3.11
    print_info "Configuring permissions to the directory ${DECORATION_DIM_ON}\"${APACHE_DIR}\"${DECORATION_BOLD_OFF}."
    set_permission_recursive "root:root" "og-rwx" ${APACHE_DIR}
    print_info "Configuring permissions to the directory ${DECORATION_DIM_ON}\"${APACHE_DIR_SBIN}\"${DECORATION_BOLD_OFF}."
    set_permission_recursive "root:root" "og-rwx" ${APACHE_DIR_SBIN}
    print_info "Configuring permissions to the directory ${DECORATION_DIM_ON}\"${APACHE_DIR_SHARE}\"${DECORATION_BOLD_OFF}."
    set_permission_recursive "root:root" "og-rwx" ${APACHE_DIR_SHARE}
    print_info "Configuring permissions to the directory ${DECORATION_DIM_ON}\"${APACHE_DIR_LIB}\"${DECORATION_BOLD_OFF}."
    set_permission_recursive "root:root" "og-rwx" ${APACHE_DIR_LIB}
    print_info "Configuring permissions to the directory ${DECORATION_DIM_ON}\"${APACHE_DIR_LOG}\"${DECORATION_BOLD_OFF}."
    set_permission_recursive "root:apache" "og-rwx" ${APACHE_DIR_LOG}
    print_info "Configuring permissions to the lock file ${DECORATION_DIM_ON}\"${APACHE_LOCK_DIR}\"${DECORATION_BOLD_OFF}."
    set_permission "root:root" "og-w" ${APACHE_LOCK_DIR}
    print_info "Configuring permissions to the directory ${DECORATION_DIM_ON}\"${APACHE_WEB_ROOT}\"${DECORATION_BOLD_OFF}."
    set_permission_recursive "apache:apache" "og-wx" ${APACHE_WEB_ROOT}

    print_info "Configuring document root file to the ${DECORATION_DIM_ON}\"${APACHE_WEB_ROOT}\"${DECORATION_BOLD_OFF}."
    set_parameter "DocumentRoot" ${APACHE_WEB_ROOT} ${APACHE_CONF}

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 8.1
    print_info "Configing the server HTTP response header to product only."
    set_parameter "ServerTokens" "Prod" ${APACHE_SECURITY_CONF}

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 8.4
    print_info "Disabling file ETag."
    set_parameter "FileETag" "None" ${APACHE_SECURITY_CONF}

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 9.1
    print_info "Configuring the amount of time the server will wait for certain events before failing a request to 10 seconds."
    set_parameter "Timeout" "10" ${APACHE_SECURITY_CONF}

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 10.1
    print_info "Configuring the size limit of the HTTP request line that will be accepted from the client to 512 bytes."
    set_parameter "LimitRequestline" "512" ${APACHE_SECURITY_CONF}

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 10.3
    print_info "Configuring the size limits of the HTTP request header allowed from the client to 1024 bytes ${DECORATION_DIM_ON}(1 KB)${DECORATION_BOLD_OFF}."
    set_parameter "LimitRequestFieldsize" "1024" ${APACHE_SECURITY_CONF}

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 10.4
    print_info "Configuring restrictions for the total size of the HTTP request body sent from the client to 102400 bytes ${DECORATION_DIM_ON}(100 KB)${DECORATION_BOLD_OFF}."
    set_parameter "LimitRequestBody" "102400" ${APACHE_SECURITY_CONF}

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 5.9
    print_info "Disabling old HTTP protocol versions."
    set_parameter "Protocols" "h2 http/1.1" ${APACHE_SECURITY_CONF}

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 5.14
    print_info "Configuring restricting browser frame options to sameorigin."
    print_info "Enabling Content Security Policy."
    set_parameter "Header always set X-Frame-Options" "\"sameorigin\"" ${APACHE_SECURITY_CONF}
    set_parameter "Header always set Content-Security-Policy" "\"default-src 'self'; frame-ancestors 'self'\"" ${APACHE_SECURITY_CONF}

    print_info "Configuring send referrer to all origins, but only the URL sans path ${DECORATION_DIM_ON}(e.g. https://example.com/)${DECORATION_BOLD_OFF}."
    set_parameter "Header always set Referrer-Policy" "\"strict-origin\"" ${APACHE_SECURITY_CONF}

    print_info "Configuring prevent browsers from incorrectly detecting non-scripts as scripts."
    set_parameter "Header always set X-Content-Type-Options" "\"nosniff\"" ${APACHE_SECURITY_CONF}

    print_info "Enabling XSS Protection."
    set_parameter "Header always set X-Xss-Protection" "\"1; mode=block\"" ${APACHE_SECURITY_CONF}

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 6.1
    print_info "Configuring the error log."
    set_parameter "LogLevel" "notice core:info" ${APACHE_SECURITY_CONF}

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 7.4 7.5 7.6 7.8 7.9 7.10
    # Settings inspired by "Mozilla SSL Configuration Generator". https://mozilla.github.io/server-side-tls/ssl-config-generator/?server=apache-2.4.39&openssl=1.1.1b&hsts=yes&profile=modern
    print_info "Adding ssl certification template to the file ${DECORATION_BOLD_ON}\"${APACHE_SECURITY_CONF}\"${DECORATION_BOLD_OFF}."
    echo -e "\n<VirtualHost *:80>" >> ${APACHE_SECURITY_CONF}
    echo -e "\t#Redirect permanent / https://site.org/" >> ${APACHE_SECURITY_CONF}
    echo -e "</VirtualHost>\n" >> ${APACHE_SECURITY_CONF}
    echo -e "\n<VirtualHost *:443>" >> ${APACHE_SECURITY_CONF}
    echo -e "\t#SSLEngine on" >> ${APACHE_SECURITY_CONF}
    echo -e "\t#SSLCertificateFile      /path/to/signed_certificate_followed_by_intermediate_certs" >> ${APACHE_SECURITY_CONF}
    echo -e "\t#SSLCertificateKeyFile   /path/to/private/key" >> ${APACHE_SECURITY_CONF}
    echo -e "\n\t# Uncomment the following directive when using client certificate authentication" >> ${APACHE_SECURITY_CONF}
    echo -e "\t#SSLCACertificateFile    /path/to/ca_certs_for_client_authentication" >> ${APACHE_SECURITY_CONF}
    echo -e "\n\t# HSTS (mod_headers is required) (15768000 seconds = 6 months)" >> ${APACHE_SECURITY_CONF}
    echo -e "\t#Header always set Strict-Transport-Security \"max-age=15768000\"" >> ${APACHE_SECURITY_CONF}
    echo -e "</VirtualHost>\n" >> ${APACHE_SECURITY_CONF}
    print_info "Disabling SSL v3.0, TLS v1.0 and TLS v1.1 protocols."
    set_parameter "SSLProtocol" "all -SSLv3 -TLSv1 -TLSv1.1" ${APACHE_SECURITY_CONF}
    print_info "Restricting weak SSL/TLS ciphers."
    set_parameter "SSLCipherSuite" "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256" ${APACHE_SECURITY_CONF}
    print_info "Enabling preference for the server's cipher preference order."
    set_parameter "SSLHonorCipherOrder" "on" ${APACHE_SECURITY_CONF}
    print_info "Disabling compression on the SSL level."
    set_parameter "SSLCompression" "off" ${APACHE_SECURITY_CONF}
    print_info "Disabling the use of TLS session tickets."
    set_parameter "SSLSessionTickets" "off" ${APACHE_SECURITY_CONF}
    print_info "Disabling support for insecure renegotiation."
    set_parameter "SSLInsecureRenegotiation" "off" ${APACHE_SECURITY_CONF}
    print_info "Enabling stapling of OCSP responses in the TLS handshake."
    set_parameter "SSLUseStapling" "on" ${APACHE_SECURITY_CONF}
    print_info "Configuring timeout for OCSP stapling queries to 5 seconds."
    set_parameter "SSLStaplingResponderTimeout" "5" ${APACHE_SECURITY_CONF}
    print_info "Disabling pass stapling related OCSP errors on to client."
    set_parameter "SSLStaplingReturnResponderErrors" "off" ${APACHE_SECURITY_CONF}
    print_info "Configuring expiring responses in the OCSP stapling cache."
    set_parameter "SSLStaplingCache" "\"shmcb:/var/run/ocsp(128000)\"" ${APACHE_SECURITY_CONF}

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 5.7
    print_info "Configuring HTTP request for the GET, POST and HEAD methods only."
    echo -e "\n<Location />" >> ${APACHE_SECURITY_CONF}
    echo -e "\tOrder allow,deny" >> ${APACHE_SECURITY_CONF}
    echo -e "\tAllow from all" >> ${APACHE_SECURITY_CONF}
    echo -e "\t<LimitExcept GET POST HEAD>" >> ${APACHE_SECURITY_CONF}
    echo -e "\t\tdeny from all" >> ${APACHE_SECURITY_CONF}
    echo -e "\t</LimitExcept>" >> ${APACHE_SECURITY_CONF}
    echo -e "</Location>\n" >> ${APACHE_SECURITY_CONF}

    # CIS Benchmark Apache server 2.4 v1.4.0 chapter 5.8
    print_info "Disabling HTTP TRACE method."
    set_parameter "TraceEnable" "off" ${APACHE_SECURITY_CONF}

    print_info "Enabling OWASP Core Rule Set."
    cp ${APACHE_MOD_SECURITY_CONF}-recommended ${APACHE_MOD_SECURITY_CONF}
    set_parameter "SecRuleEngine" "On" ${APACHE_MOD_SECURITY_CONF}

    systemctl start apache2
}

#===  FUNCTION  ================================================================
#          NAME: mariadb_harden
#   DESCRIPTION: Install and harden MariaDB.
#     PARAMETER: ---
#===============================================================================
function mariadb_harden {

    print_info "${DECORATION_BOLD_ON}HARDENING MARIADB${DECORATION_BOLD_OFF}"

    print_info "Installing MariaDB server."
    curl -sS https://downloads.mariadb.com/MariaDB/mariadb_repo_setup | sudo bash
    apt -y install mariadb-server

    print_info "Backing up MariaDB configuration files."
    backup_file ${MARIADB_CNF}

    print_info "Executing the MySQL installation security script. It's recommented to answer yes ${DECORATION_DIM_ON}[Y]${DECORATION_DIM_OFF} to all question."
    password_generate
    print_info "You can use this autogenerated password for the mariadb root accout:\n${DECORATION_BOLD_ON}$PASSWORD_GENERATED${DECORATION_BOLD_OFF}"
    print_info "Press any key to start execution."
    read -n 1 -s
    # fix script bug
    CURRENT_WORKING_DIRECTORY=$(pwd)
    cd /
    mysql_secure_installation
    cd ${CURRENT_WORKING_DIRECTORY}

    print_info "Stopping MariaDB service."
    systemctl stop mariadb

    append_to_file "[mysqld]" ${MARIADB_CNF}
    print_info "Changing MariaDB port from input."
    print_info "Please enter port to MariaDB server ${DECORATION_DIM_ON}(for default port press enter)${DECORATION_DIM_OFF}:"
    read MARIADB_PORT
    if [[ ${MARIADB_PORT} = "" ]]; then
        MARIADB_PORT="3306"
    else
        MARIADB_PORT=$((10#${MARIADB_PORT//[!0-9]/}))
    fi
    print_info "Configuring MariaDB port to ${MARIADB_PORT}."
    set_parameter "port =" ${MARIADB_PORT} ${MARIADB_CNF}

    print_info "Disabling MariaDB command history logging."
    rm -rf ${CURRENT_USER_HOME_DIR}/.mysql_history
    ln -s /dev/null ${CURRENT_USER_HOME_DIR}/.mysql_history
    export MYSQL_HISTFILE=/dev/null

    print_info "Configuring acceptance of connections only from within the localhost"
    set_parameter "bind-address =" "127.0.0.1" ${MARIADB_CNF}

    print_info "Disabling local_infile."
    set_parameter "local-infile =" "0" ${MARIADB_CNF}

    print_info "Enabling logging."
    set_parameter "general-log =" "0" ${MARIADB_CNF}

    print_info "Starting MariaDB service."
    systemctl start mariadb

}

#===  FUNCTION  ================================================================
#          NAME: php_harden
#   DESCRIPTION: Install and harden PHP.
#     PARAMETER: ---
#===============================================================================
function php_harden {

    print_info "${DECORATION_BOLD_ON}HARDENING PHP${DECORATION_BOLD_OFF}"

    print_info "Installing PHP."
    apt -y install python-software-properties
    # Fix issue with non-UTF-8 locales. https://github.com/oerdnj/deb.sury.org/issues/56
    export LC_ALL=C.UTF-8
    add-apt-repository -y ppa:ondrej/php
    apt-key update
    fix_apt_list_lock
    apt update
    apt -y install php7.2 php7.2-mysql

    print_info "Backing up configuration files."
    backup_file ${PHP_INI}

    print_info "Disabling restriction information leakage."
    set_parameter "expose_php =" "0" ${PHP_INI}

    print_info "Disabling error messages."
    set_parameter "display_errors =" "0" ${PHP_INI}
    set_parameter "display_startup_errors  =" "0" ${PHP_INI}
    set_parameter "html_errors =" "0" ${PHP_INI}

    print_info "Enabling logging errors."
    set_parameter "log_errors =" "1" ${PHP_INI}

    # Lynis recommendation [test:PHP-2376]
    print_info "Turning off remote code execution."
    set_parameter "allow_url_fopen =" "0" ${PHP_INI}
    set_parameter "allow_url_include =" "0" ${PHP_INI}

    print_info "Limiting post size to 100 KB."
    set_parameter "post_max_size =" "100K" ${PHP_INI}

    print_info "Disabling dangerous functions."
    set_parameter "disable_functions =" "pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,curl_exec,curl_multi_exec,parse_ini_file,show_source,symlink,dl,escapeshellarg,escapeshellcmd,phpinfo,ini_set,php_uname,diskfreespace,tmpfile,link,set_time_limit,highlight_file,virtual,posix_ctermid,posix_getcwd,posix_getegid,posix_geteuid,posix_getgid,posix_getgrgid,posix_getgrnam,posix_getgroups,posix_getlogin,posix_getpgid,posix_getpgrp,posix_getpid,posix_getppid,posix_getpwnam,posix_getpwuid,posix_getrlimit,posix_getsid,posix_getuid,posix_isatty,posix_kill,posix_mkfifo,posix_setegid,posix_seteuid,posix_setgid,posix_setpgid,posix_setsid,posix_setuid,posix_times,posix_ttyname,posix_uname,proc_open,proc_close,proc_get_status,proc_nice,proc_terminate,chgrp,chmod,chown,lchgrp,lchown,putenv,passthru,exec,shell_exec,system" ${PHP_INI}

    print_info "Limiting directory execution to ${DECORATION_DIM_ON}\"${APACHE_WEB_ROOT}\"${DECORATION_DIM_OFF}."
    set_parameter "open_basedir =" ${APACHE_WEB_ROOT} ${PHP_INI}

    print_info "Restricting the acceptation of uninitialized session ID."
    set_parameter "session.use_strict_mode =" "1" ${PHP_INI}

    print_info "Enabling cookies accessible only through the HTTP protocol."
    set_parameter "session.cookie_httponly =" "1" ${PHP_INI}

    print_info "Configuring the sending of cookies only over secure connections."
    set_parameter "session.cookie_secure =" "1" ${PHP_INI}

}

#===  FUNCTION  ================================================================
#          NAME: linux_firewall
#   DESCRIPTION: Setup firewall
#     PARAMETER: ---
#===============================================================================
function linux_firewall {

    print_info "Denying all incoming network traffic."
    ufw default deny incoming

    print_info "Allowing all outgoing network traffic."
    ufw default allow outgoing

    print_info "Allowing network traffic for OpenSSH."
    ufw allow in ${SSH_PORT}

    print_info "Allowing incoming network traffic for Apache."
    ufw allow in 80,443/tcp

    print_info "Enabling logging."
    ufw logging on

    print_info "Enabling UFW."
    ufw enable

}

#===  FUNCTION  ================================================================
#          NAME: linux_passwords
#   DESCRIPTION: Harden linux passwords
#     PARAMETER: ---
#===============================================================================
function linux_passwords {

    print_info "Installing libpam-pwquality."
    apt -y install libpam-pwquality

    print_info "Backing up passwords configuration files."
    backup_file ${PWQUALITY_CONF}
    backup_file ${LOGIN_DEFS}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.3.1
    print_info "Configuring password creation requirement."
    set_parameter "minlen =" "14" ${PWQUALITY_CONF}
    set_parameter "dcredit =" "-1" ${PWQUALITY_CONF}
    set_parameter "ucredit =" "-1" ${PWQUALITY_CONF}
    set_parameter "ocredit =" "-1" ${PWQUALITY_CONF}
    set_parameter "lcredit =" "-1" ${PWQUALITY_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.4.1.1
    print_info "Configuring password expiration to 365 days."
    set_parameter "PASS_MAX_DAYS" "365" ${LOGIN_DEFS}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.4.1.2
    print_info "Configuring minimum days between password changes to 7."
    set_parameter "PASS_MIN_DAYS" "7" ${LOGIN_DEFS}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.4.1.3
    print_info "Configuring password expiration warning days to 90."
    set_parameter "PASS_WARN_AGE" "90" ${LOGIN_DEFS}

}

#===  FUNCTION  ================================================================
#          NAME: linux_filesystem
#   DESCRIPTION: Harden linux filesystem.
#     PARAMETER: ---
#===============================================================================
function linux_filesystem {

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 1.1.1.1
    print_info "Disabling cramfs filesystem type."
    touch ${MODPROBE_CRAMFS}
    set_parameter "install cramfs" "/bin/true" ${MODPROBE_CRAMFS}
    rmmod -s cramfs

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 1.1.1.2
    print_info "Disabling freevxfs filesystem type."
    touch ${MODPROBE_FREEVXFS}
    set_parameter "install freevxfs" "/bin/true" ${MODPROBE_FREEVXFS}
    rmmod -s freevxfs

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 1.1.1.3
    print_info "Disabling jffs2 filesystem type."
    touch ${MODPROBE_JFFS2}
    set_parameter "install jffs2" "/bin/true" ${MODPROBE_JFFS2}
    rmmod -s jffs2

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 1.1.1.4
    print_info "Disabling hfs filesystem type."
    touch ${MODPROBE_HFS}
    set_parameter "install hfs" "/bin/true" ${MODPROBE_HFS}
    rmmod -s hfs

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 1.1.1.5
    print_info "Disabling hfsplus filesystem type."
    touch ${MODPROBE_HFSPLUS}
    set_parameter "install hfsplus" "/bin/true" ${MODPROBE_HFSPLUS}
    rmmod -s hfsplus

    # CIS Benchmark Linux Independed Distribution v1.1.0 chapter 1.1.1.6
    print_info "Disabling squashfs filesystem type."
    touch ${MODPROBE_SQUASHFS}
    set_parameter "install squashfs" "/bin/true" ${MODPROBE_SQUASHFS}
    rmmod -s squashfs

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 1.1.1.6
    print_info "Disabling udf filesystem type."
    touch ${MODPROBE_UDF}
    set_parameter "install udf" "/bin/true" ${MODPROBE_UDF}
    rmmod -s udf

    # Lynis recommendation [test:STRG-1840]
    print_info "Disabling driver for USB storage"
    touch ${MODPROBE_USB}
    set_parameter "install usb-storage" "/bin/true" ${MODPROBE_USB}

    backup_file ${FSTAB}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 1.1.2 1.1.3 1.1.4
    print_info "Do you want to mount the directory /tmp to the RAM (recommended)? ${DECORATION_DIM_ON}(add following to ${FSTAB}: tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0)${DECORATION_DIM_OFF} [Y/n]"
    read ANSWER_RESTART
    if [[ "${ANSWER_RESTART}" != "n" ]]; then
        print_info "Separating partition for /tmp directory with rw, nosuid, nodev, noexec and relatime option."
        set_parameter "tmpfs /tmp tmpfs" "rw,nosuid,nodev,noexec,relatime 0 0" ${FSTAB}
    fi

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 1.1.14 1.1.15 1.1.16
    print_info "Do you want to harden the /dev/shm partition (recommended)? ${DECORATION_DIM_ON}(add following to ${FSTAB}: tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime 0 0)${DECORATION_DIM_OFF} [Y/n]"
    read ANSWER_RESTART
    if [[ "${ANSWER_RESTART}" != "n" ]]; then
        print_info "Mounting partition for /dev/shm directory with rw, nosuid, nodev, noexec and relatime option."
        set_parameter "tmpfs /dev/shm tmpfs" "rw,nosuid,nodev,noexec,relatime 0 0" ${FSTAB}
    fi

    # Lynis recommendation [test:FILE-6344]
    print_info "Do you want to harden the /proc partition (recommended)? ${DECORATION_DIM_ON}(add following to ${FSTAB}: proc /proc proc defaults,hidepid=2 0 0)${DECORATION_DIM_OFF} [Y/n]"
    read ANSWER_RESTART
    if [[ "${ANSWER_RESTART}" != "n" ]]; then
        print_info "Mounting partition for /dev/proc directory with defaults and hidepid=2 option."
        set_parameter "proc /proc proc" "defaults,hidepid=2 0 0" ${FSTAB}
    fi

    # Lynis recommendation [test:STRG-1842]
    print_info "Lock-down of USB devices."
    for host in /sys/bus/usb/devices/usb*
    do
        echo 0 > ${host}/authorized
        echo 0 > ${host}/authorized_default
    done

}

#===  FUNCTION  ================================================================
#          NAME: linux_network_protocols
#   DESCRIPTION: Harden newtwok protocols
#     PARAMETER: ---
#===============================================================================
function linux_network_protocols {

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.5.1
    print_info "Disabling DCCP network protocol."
    touch ${MODPROBE_DCCP}
    set_parameter "install dccp" "/bin/true" ${MODPROBE_DCCP}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.5.2
    print_info "Disabling SCTP network protocol."
    touch ${MODPROBE_SCTP}
    set_parameter "install sctp" "/bin/true" ${MODPROBE_SCTP}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.5.3
    print_info "Disabling RDS network protocol."
    touch ${MODPROBE_RDS}
    set_parameter "install rds" "/bin/true" ${MODPROBE_RDS}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.5.4
    print_info "Disabling TIPC network protocol."
    touch ${MODPROBE_TIPC}
    set_parameter "install tipc" "/bin/true" ${MODPROBE_TIPC}

}

#===  FUNCTION  ================================================================
#          NAME: linux_kernel
#   DESCRIPTION: Harden linux kernel
#     PARAMETER: ---
#===============================================================================
function linux_kernel {

    print_info "Preventing issues to apply sysctl settings on reboot."
    add_crontab_task "@reboot root /bin/sleep 5 && /sbin/sysctl --system"

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 1.5.1
    print_info "Core dumps restriction."
    backup_file ${SECURITY_LIMITS_CONF}
    backup_file ${SYSCTL_CONF}
    set_parameter "* hard core" "0" ${SECURITY_LIMITS_CONF}
    set_parameter "fs.suid_dumpable =" "0" ${SYSCTL_CONF}

    # Lynis recommendation [test:KRNL-6000]
    print_info "Configuring the coredump filename to core.PID"
    set_parameter "kernel.core_uses_pid =" "1" ${SYSCTL_CONF}

    # Lynis recommendation [test:KRNL-6000]
    print_info "Disabling SysRq functions."
    set_parameter "kernel.sysrq =" "0" ${SYSCTL_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 1.5.3
    print_info "Enabling address space layout randomization ${DECORATION_DIM_ON}(ASLR)${DECORATION_DIM_OFF}."
    set_parameter "kernel.randomize_va_space =" "2" ${SYSCTL_CONF}

    # Lynis recommendation [test:KRNL-6000]
    print_info "Cofiguring the kernel pointers printed using %pK to be replaced with 0's regardless of privileges."
    set_parameter "kernel.kptr_restrict =" "2" ${SYSCTL_CONF}

    # Lynis recommendation [test:KRNL-6000]
    print_info "Configuring dmesg so users must have CAP_SYSLOG to use it."
    set_parameter "kernel.dmesg_restrict =" "1" ${SYSCTL_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.1.1
    print_info "Disabling IP forwarding."
    set_parameter "net.ipv4.ip_forward =" "0" ${SYSCTL_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.1.2
    print_info "Disabling packet redirect sending."
    set_parameter "net.ipv4.conf.all.send_redirects =" "0" ${SYSCTL_CONF}
    set_parameter "net.ipv4.conf.default.send_redirects =" "0" ${SYSCTL_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.2.1
    print_info "Disabling the acceptance of source routed packets."
    set_parameter "net.ipv4.conf.all.accept_source_route =" "0" ${SYSCTL_CONF}
    set_parameter "net.ipv4.conf.default.accept_source_route =" "0" ${SYSCTL_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.2.2
    print_info "Disabling ICMP redirects."
    set_parameter "net.ipv4.conf.all.accept_redirects =" "0" ${SYSCTL_CONF}
    set_parameter "net.ipv4.conf.default.accept_redirects =" "0" ${SYSCTL_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.2.3
    print_info "Disabling secure ICMP redirects."
    set_parameter "net.ipv4.conf.all.secure_redirects =" "0" ${SYSCTL_CONF}
    set_parameter "net.ipv4.conf.default.secure_redirects =" "0" ${SYSCTL_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.2.4
    print_info "Enabling suspicious packets log."
    set_parameter "net.ipv4.conf.all.log_martians =" "1" ${SYSCTL_CONF}
    set_parameter "net.ipv4.conf.default.log_martians =" "1" ${SYSCTL_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.2.5
    print_info "Enabling ignoring broadcast ICMP requests."
    set_parameter "net.ipv4.icmp_echo_ignore_broadcasts =" "1" ${SYSCTL_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.2.6
    print_info "Enabling ignoring bogus ICMP responses."
    set_parameter "net.ipv4.icmp_ignore_bogus_error_responses =" "1" ${SYSCTL_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.2.7
    print_info "Enabling reverse path filtering."
    set_parameter "net.ipv4.conf.all.rp_filter =" "1" ${SYSCTL_CONF}
    set_parameter "net.ipv4.conf.default.rp_filter =" "1" ${SYSCTL_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.2.8
    print_info "Enabling TCP SYN Cookies."
    set_parameter "net.ipv4.tcp_syncookies =" "1" ${SYSCTL_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.3.1
    print_info "Disabling IPv6 router advertisements."
    set_parameter "net.ipv6.conf.all.accept_ra =" "0" ${SYSCTL_CONF}
    set_parameter "net.ipv6.conf.default.accept_ra =" "0" ${SYSCTL_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.3.2
    print_info "Disabling IPv6 redirects."
    set_parameter "net.ipv6.conf.all.accept_redirects =" "0" ${SYSCTL_CONF}
    set_parameter "net.ipv6.conf.default.accept_redirects =" "0" ${SYSCTL_CONF}

}

#===  FUNCTION  ================================================================
#          NAME: linux_misc
#   DESCRIPTION: Harden linux miscellaneous
#     PARAMETER: ---
#===============================================================================
function linux_misc {

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 2.1.8  2.2.3 2.2.4
    # Lynis recommendation [test:PKGS-7346] [test:HRDN-7220]
    print_info "Removing avahi server."
    print_info "Removing binutils."
    print_info "Removing cups."
    print_info "Removing gcc."
    print_info "Removing make."
    print_info "Removing snapd."
    print_info "Removing telnet client."
    print_info "Disabling bluetooth."
    apt -y autoremove --purge avahi-daemon binutils cups cups-common gcc make snapd telnet
    systemctl disable bluetooth
    print_info "Removing the remaining of unnecessary files."
    rm -rf ${CUPS_DIR} ${HLIP_DIR} ${AVAHI_DIR}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 2.2.1.1 4.1.2 4.2.1.1 5.1.1
    # Lynis recommendation [test:PKGS-7346] [test:ACCT-9622] [test:ACCT-9626] [test:ACCT-9628] [test:FINT-4350] [test:MALW-3280] [TOOL-5190] [test:USB-3000]
    print_info "Installing and enabling process accounting."
    print_info "Installing aide ${DECORATION_DIM_ON}(integrity tool)${DECORATION_DIM_OFF}."
    print_info "Installing apt-show-versions."
    print_info "Installing and enabling ARP monitoring."
    print_info "Installing and enabling auditd to collect accounting."
    print_info "Installing ClamAV."
    print_info "Installing debsums."
    print_info "Installing htop."
    print_info "Installing and enabling fail2ban."
    print_info "Installing and enabling sysstat to collect accounting."
    print_info "Installing and enabling ntp for time synchronization."
    print_info "Installing and enabling USBGuard."
    print_info "Installing unattended-upgrades."
    print_info "Enabling cron."
    print_info "Enabling rsyslog."
    add-apt-repository -y ppa:altj/usbguard
    fix_apt_list_lock
    apt update
    apt -y install acct aide aide-common apt-show-versions arpwatch auditd clamav clamav-daemon debsums fail2ban htop ntp sysstat unattended-upgrades usbguard
    systemctl enable acct auditd arpwatch cron fail2ban ntp rsyslog sysstat usbguard
    set_parameter "ENABLED=" "\"true"\" ${SYSSTAT} ""

    print_info "Backing up USBGuard configuration files."
    backup_file ${USBGURAD_CONF}

    # Lynis recommendation [test:USB-3000]
    print_info "Disabling restore controller device state in USBGuard."
    set_parameter "RestoreControllerDeviceState" "false" ${USBGURAD_CONF} "="
    print_info "Configuring USB controllers that are already connected when the daemon starts to evaluate the ruleset for every present device in USBGuard."
    set_parameter "PresentControllerPolicy" "apply-policy" ${USBGURAD_CONF} "="
    print_info "Configuring devices that are already connected when the daemon starts to evaluate the ruleset for every present device in USBGuard."
    set_parameter "PresentDevicePolicy" "apply-policy" ${USBGURAD_CONF} "="
    print_info "Configuring USB devices that are already connected *after* the daemon starts to evaluate the ruleset for every present device in USBGuard."
    set_parameter "InsertedDevicePolicy" "apply-policy" ${USBGURAD_CONF} "="
    print_info "Configuring devices that don't match any rule in the policy to block in USBGuard."
    set_parameter "ImplicitPolicyTarget" "block" ${USBGURAD_CONF} "="
    print_info "Configuring rule set file path to ${DECORATION_DIM_ON}\"%sysconfdir%/usbguard/rules.conf\"${DECORATION_DIM_OFF}."
    touch /etc/usbguard/rules.conf
    set_parameter "RuleFile" "/etc/usbguard/rules.conf" ${USBGURAD_CONF} "="

    print_info "Backing up auditd configuration files."
    backup_file ${AUDITD_CONF}
    backup_file ${AUDITD_RULES}

    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${AUDITD_LOG}\"${DECORATION_DIM_OFF}."
    chmod 0600 ${AUDITD_LOG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.1.1
    print_info "Configuring audit log storage size to 25 MiB."
    set_parameter "max_log_file =" "25" ${AUDITD_CONF}

    set_parameter "space_left_action =" "SYSLOG" ${AUDITD_CONF}
    set_parameter "admin_space_left_action =" "SYSLOG" ${AUDITD_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.1.3
    print_info "Configuring the saving of the audit log, when the max file size limit has been reached."
    set_parameter "max_log_file_action =" "keep_logs" ${AUDITD_CONF}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.4
    print_info "Capturing events where the system date and time has been modified in auditd."
    append_to_file "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" ${AUDITD_RULES}
    append_to_file "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" ${AUDITD_RULES}
    append_to_file "-a always,exit -F arch=b64 -S clock_settime -k time-change" ${AUDITD_RULES}
    append_to_file "-a always,exit -F arch=b32 -S clock_settime -k time-change" ${AUDITD_RULES}
    append_to_file "-w /etc/localtime -p wa -k time-change" ${AUDITD_RULES}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.5
    print_info "Monitoring events affecting the group , passwd, shadow and gshadow files in auditd."
    append_to_file "-w /etc/group -p wa -k identity" ${AUDITD_RULES}
    append_to_file "-w /etc/passwd -p wa -k identity" ${AUDITD_RULES}
    append_to_file "-w /etc/gshadow -p wa -k identity" ${AUDITD_RULES}
    append_to_file "-w /etc/shadow -p wa -k identity" ${AUDITD_RULES}
    append_to_file "-w /etc/security/opasswd -p wa -k identity" ${AUDITD_RULES}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.6
    print_info "Monitoring changes to the network environment files or system calls in auditd."
    append_to_file "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" ${AUDITD_RULES}
    append_to_file "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" ${AUDITD_RULES}
    append_to_file "-w /etc/issue -p wa -k system-locale" ${AUDITD_RULES}
    append_to_file "-w /etc/issue.net -p wa -k system-locale" ${AUDITD_RULES}
    append_to_file "-w /etc/hosts -p wa -k system-locale" ${AUDITD_RULES}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.7
    print_info "Monitoring events that modify the system's Mandatory Access Controls in auditd."
    append_to_file "-w /etc/apparmor/ -p wa -k MAC-policy" ${AUDITD_RULES}
    append_to_file "-w /etc/apparmor.d/ -p wa -k MAC-policy" ${AUDITD_RULES}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.8
    print_info "Monitoring login and logout events in auditd."
    append_to_file "-w /var/log/faillog -p wa -k logins" ${AUDITD_RULES}
    append_to_file "-w /var/log/lastlog -p wa -k logins" ${AUDITD_RULES}
    append_to_file "-w /var/log/tallylog -p wa -k logins" ${AUDITD_RULES}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.9
    print_info "Monitoring session initiation events in auditd."
    append_to_file "-w /var/run/utmp -p wa -k session" ${AUDITD_RULES}
    append_to_file "-w /var/log/wtmp -p wa -k logins" ${AUDITD_RULES}
    append_to_file "-w /var/log/btmp -p wa -k logins" ${AUDITD_RULES}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.10
    print_info "Monitoring discretionary access control permission modification in auditd."
    append_to_file "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" ${AUDITD_RULES}
    append_to_file "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" ${AUDITD_RULES}
    append_to_file "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" ${AUDITD_RULES}
    append_to_file "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" ${AUDITD_RULES}
    append_to_file "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" ${AUDITD_RULES}
    append_to_file "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" ${AUDITD_RULES}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.11
    print_info "Monitoring unsuccessful unauthorized file access attempts in auditd."
    append_to_file "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" ${AUDITD_RULES}
    append_to_file "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" ${AUDITD_RULES}
    append_to_file "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" ${AUDITD_RULES}
    append_to_file "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" ${AUDITD_RULES}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.13
    print_info "Monitoring successful file system mounts in auditd."
    append_to_file "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" ${AUDITD_RULES}
    append_to_file "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" ${AUDITD_RULES}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.14
    print_info "Monitoring file deletion events by users in auditd."
    append_to_file "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" ${AUDITD_RULES}
    append_to_file "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" ${AUDITD_RULES}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.15
    print_info "Monitoring changes to system administration scope (sudoers) in auditd."
    append_to_file "-w /etc/sudoers -p wa -k scope" ${AUDITD_RULES}
    append_to_file "-w /etc/sudoers.d/ -p wa -k scope" ${AUDITD_RULES}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.16
    print_info "Monitoring system administrator actions (sudolog) in auditd."
    append_to_file "-w /var/log/sudo.log -p wa -k actions" ${AUDITD_RULES}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.17
    print_info "Monitoring kernel module loading and unloading in auditd."
    append_to_file "-w /sbin/insmod -p x -k modules" ${AUDITD_RULES}
    append_to_file "-w /sbin/rmmod -p x -k modules" ${AUDITD_RULES}
    append_to_file "-w /sbin/modprobe -p x -k modules" ${AUDITD_RULES}
    append_to_file "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" ${AUDITD_RULES}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 4.1.18
    print_info "Setting system audit so that audit rules cannot be modified with auditctl."
    append_to_file "-e 2" ${AUDITD_RULES}

    # Lynis recommendation [test:BANN-7126]
    print_info "Configuring the text, that is shown before the authorization, when local users and network users are connected."
    backup_file ${ISSUE}
    echo "********************************************************************" > ${ISSUE}
    echo "*                                                                  *" >> ${ISSUE}
    echo "* This system is for the use of authorized users only.  Usage of   *" >> ${ISSUE}
    echo "* this system may be monitored and recorded by system personnel.   *" >> ${ISSUE}
    echo "*                                                                  *" >> ${ISSUE}
    echo "* Anyone using this system expressly consents to such monitoring   *" >> ${ISSUE}
    echo "* and is advised that if such monitoring reveals possible          *" >> ${ISSUE}
    echo "* evidence of criminal activity, system personnel may provide the  *" >> ${ISSUE}
    echo "* evidence from such monitoring to law enforcement officials.      *" >> ${ISSUE}
    echo "*                                                                  *" >> ${ISSUE}
    echo "********************************************************************" >> ${ISSUE}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.4.5
    print_info "Configuring default user shell timeout to 300 seconds ${DECORATION_DIM_ON}(5 minutes)${DECORATION_DIM_OFF}."
    export TMOUT=300
    readonly TMOUT
    set_parameter "TMOUT=" "300" ${PROFILE} ""
    append_to_file "readonly TMOUT" ${PROFILE}

    print_info "Press any key to start configuring timezone."
    read -n 1 -s
    tzselect

    print_info "Enabling automatical update every day at 5:00 AM."
    echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
    dpkg-reconfigure -f noninteractive unattended-upgrades
    backup_file ${APT_TIMER}
    backup_file ${APT_PERIODIC_CONF}
    set_parameter "OnCalendar=" "05:00" ${APT_TIMER} ""
    set_parameter "RandomizedDelaySec=" "0" ${APT_TIMER} ""
    set_parameter "APT::Periodic::Download-Upgradeable-Packages" "\"1\";" ${APT_PERIODIC_CONF}
    set_parameter "APT::Periodic::AutocleanInterval" "\"7\";" ${APT_PERIODIC_CONF}
    set_parameter "APT::Periodic::Unattended-Upgrade" "\"1\";" ${APT_PERIODIC_CONF}

    # Lynis recommendation [test:NETW-2705]
    print_info "Configuring Cloudflare and Google as DNS resolvers"
    append_to_file "nameserver 1.1.1.1" ${RESOLV_CONF}
    append_to_file "nameserver 1.0.0.1" ${RESOLV_CONF}
    append_to_file "nameserver 8.8.8.8" ${RESOLV_CONF}
    append_to_file "nameserver 8.8.4.4" ${RESOLV_CONF}

}

#===  FUNCTION  ================================================================
#          NAME: linux_permissions
#   DESCRIPTION: Hardner linux permissions
#     PARAMETER: ---
#===============================================================================
function linux_permissions {

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 1.7.1.5
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${ISSUE}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "0644" ${ISSUE}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 1.7.1.6
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${ISSUE_NET}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "0644" ${ISSUE_NET}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 1.4.1
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${GRUB_CONFIG}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "og-rwx" ${GRUB_CONFIG}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.4.4
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${HOSTS_ALLOW}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "0644" ${HOSTS_ALLOW}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 3.4.5
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${HOSTS_DENY}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "0644" ${HOSTS_DENY}

    print_info "Configuring permissions to the directory ${DECORATION_DIM_ON}\"${LOG_DIRECTORY}\"${DECORATION_DIM_OFF}."
    chmod -R g-wx,o-rwx ${LOG_DIRECTORY}*

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.1.2
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${CRON_CRONTAB}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "og-rwx" ${CRON_CRONTAB}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.1.3
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${CRON_HOURLY}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "og-rwx" ${CRON_HOURLY}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.1.4
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${CRON_DAILY}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "og-rwx" ${CRON_DAILY}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.1.5
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${CRON_WEEKLY}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "og-rwx" ${CRON_WEEKLY}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.1.6
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${CRON_MONTHLY}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "og-rwx" ${CRON_MONTHLY}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.1.7
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${CRON_D}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "og-rwx" ${CRON_D}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 6.1.2
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${PASSWD}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "0644" ${PASSWD}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 6.1.3
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${SHADOW}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "0644" ${SHADOW}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 6.1.4
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${GROUP}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "0644" ${GROUP}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 6.1.5
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${GSHADOW}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "0644" ${GSHADOW}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 6.1.6
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${PASSWD_}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "0644" ${PASSWD_}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 6.1.7
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${SHADOW_}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "0644" ${SHADOW_}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 6.1.8
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${GROUP_}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "0644" ${GROUP_}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 6.1.9
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${GSHADOW_}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "0644" ${GSHADOW_}

    # Tiger recommendation (boot02).
    print_info "Configuring permissions to the file ${DECORATION_DIM_ON}\"${GRUB_MENU}\"${DECORATION_DIM_OFF}."
    set_permission "root:root" "0600" ${GRUB_MENU}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 1.1.25
    print_info "Configuring sticky bit on all world-writable directories."
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

    # Lynis recommendation [test:AUTH-9328]
    print_info "Configuring the default umask values to 027."
    set_parameter "UMASK" "027" ${LOGIN_DEFS}
    set_parameter "umask" "027" ${INIT_RC}

    # CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 5.4.4
    print_info "Configuring the default user umask to 027."
    backup_file ${PROFILE}
    backup_file ${BASHRC}
    echo -e "\nif [ $UID -gt 199 ] && [ "`id -gn`" = "`id -un`" ]; then" >> ${PROFILE}
    echo -e "\tumask 027" >> ${PROFILE}
    echo -e "else" >> ${PROFILE}
    echo -e "\tumask 027" >> ${PROFILE}
    echo -e "fi" >> ${PROFILE}
    echo -e "\nif [ $UID -gt 199 ] && [ "`id -gn`" = "`id -un`" ]; then" >> ${BASHRC}
    echo -e "\tumask 027" >> ${BASHRC}
    echo -e "else" >> ${BASHRC}
    echo -e "\tumask 027" >> ${BASHRC}
    echo -e "fi" >> ${BASHRC}

}

#===  FUNCTION  ================================================================
#          NAME: linux_harden
#   DESCRIPTION: Harden PHP configuration.
#     PARAMETER: ---
#===============================================================================
function linux_harden {

    print_info "${DECORATION_BOLD_ON}HARDENING LINUX${DECORATION_BOLD_OFF}"

    linux_firewall

    linux_passwords

    linux_filesystem

    linux_network_protocols

    linux_kernel

    linux_misc

    linux_permissions

}

# check if skript run as root
if [[ $UID -ne 0 ]];then
    (>&2 echo -e "${COLOR_RED}Non root user. ${DECORATION_BOLD_ON}Please run as root.${DECORATION_BOLD_OFF}${COLOR_DEFAULT}")
    exit 1
fi

# test an internet connection
wget -q --spider 1.1.1.1
if [[ ${UID} -ne 0 ]];then
    (>&2 echo -e "${COLOR_RED}No internet connection.${COLOR_DEFAULT}")
    exit 2
fi

echo -e "${COLOR_244}    _______________  _____  ____________  __${COLOR_DEFAULT}"
echo -e "${COLOR_245}   / __/ __/ ___/ / / / _ \/  _/_  __/\ \/ /${COLOR_DEFAULT}"
echo -e "${COLOR_246}  _\ \/ _// /__/ /_/ / , _// /  / /    \  /${COLOR_DEFAULT}"
echo -e "${COLOR_247} /___/___/\___/\____/_/|_/___/ /_/     /_/${COLOR_DEFAULT}\n"
echo -e "${COLOR_248}    __ _____   ___  ___  _____  _______  _______${COLOR_DEFAULT}"
echo -e "${COLOR_249}   / // / _ | / _ \/ _ \/ __/ |/ /  _/ |/ / ___/${COLOR_DEFAULT}"
echo -e "${COLOR_250}  / _  / __ |/ , _/ // / _//    // //    / (_ /${COLOR_DEFAULT}"
echo -e "${COLOR_251} /_//_/_/ |_/_/|_/____/___/_/|_/___/_/|_/\___/${COLOR_DEFAULT}\n"
echo -e "${COLOR_252}    ____________  _______  ______${COLOR_DEFAULT}"
echo -e "${COLOR_253}   / __/ ___/ _ \/  _/ _ \/_  __/${COLOR_DEFAULT}"
echo -e "${COLOR_254}  _\ \/ /__/ , _// // ___/ / /${COLOR_DEFAULT}"
echo -e "${COLOR_255} /___/\___/_/|_/___/_/    /_/${COLOR_DEFAULT}\n"
echo -e " Version 1.0 ~ © 2019 Michal Olenčin ${DECORATION_DIM_ON}(michal@olencin.com)${DECORATION_DIM_OFF}\n"

# CIS Benchmark Ubuntu 16.04 LTS v1.1.0 chapter 1.8
print_info "Updating packages."
fix_apt_list_lock
apt update
apt -y full-upgrade


backup_file ${CRON_CRONTAB}

ssh_harden

apache_harden

mariadb_harden

php_harden

linux_harden

print_info "Removing unnecessary packages and cache."
apt update
apt -y upgrade
apt autoclean
apt clean
apt autoremove

print_info "${COLOR_GREEN}${DECORATION_BOLD_ON}Script ended successfully.${DECORATION_BOLD_OFF}${COLOR_DEFAULT}"

print_info "It's recommented to run command ${DECORATION_DIM_ON}\"aideinit\"${DECORATION_DIM_OFF} to generate a database for AIDE."

print_info "Do you want restart the machine (recommended)? [Y/n]"
read ANSWER_RESTART
if [[ "${ANSWER_RESTART}" != "n" ]]; then
    reboot
fi

exit 0