# Automated securing of Linux web server

[![asciicast](https://asciinema.org/a/243737.svg)](https://asciinema.org/a/243737)

This is a hardening script to configure and harden Linux Ubuntu Servers after a clean installation. It installs and configures OpenSSH, Apache 2.4, MariaDB 10.3 and PHP 7.2. It also configures Linux, specifically the firewall, passwords, filesystem, network protocols, kernel, permissions, uninstalls unnecessary packages and installs and configures recommended security programs.

[![asciicast](https://asciinema.org/a/243741.svg)](https://asciinema.org/a/243741)

This hardening script reached in the auditing tool [Lynis](https://github.com/CISOfy/Lynis) score **97**.

## Getting Started

### Requirements :construction:

Before you run the script, make sure that you fulfill the following requirements:

1. Clean installation of the Ubuntu Server 16.04.4 64-bit *(also works on Ubuntu Server 18.04.2 64-bit, other Ubuntu versions are not tested)*.
2. Stable internet connection.
3. Execution permission for [script.sh](script.sh).
4. You are logged in as a user with root privileges *(not **root** user, because you will not be able to log in via the SSH.* `PermitRootLogin` *will be disabled)*.

If you are not logged in as a user with root privileges and you didn't create it yet, you can do it by running the following commands:

```
adduser USERNAME
usermod -aG sudo USERNAME
su USERNAME
```

### Usage :white_check_mark:

You can execute the script with the following command:

```
sudo chmod a+x script.sh && sudo ./script.sh
```
or
```
sudo chmod a+x script.sh
sudo ./script.sh
```

### What the script does:question:

Installs and hardens configurations as follows:

- **Linux**
  - firewall
  - passwords
  - filesystem
  - network protocols
  - kernel
  - permissions
  - uninstalls unnecessary packages
  - installs and configures recommended packages
- **OpenSSH**
- **Apache 2.4**
- **MariaDB 10.3**
- **PHP 7.2**

## Contributing :busts_in_silhouette:

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Author :boy:

* **Michal Olenčin** :bowtie: - michal@olencin.com

## License :copyright:

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE.md](LICENSE.md) file for details

## Other

An article about this project was published in:

- [2019 IEEE 15th International Scientific Conference on Informatics *(ISBN 978-1-7281-3181-8, pages 491-496)*](https://ieeexplore.ieee.org/document/9119272)
- [IPSI BgD Transactions on Internet Research *(ISSN 1820-4503, pages 61-68)*](http://ipsitransactions.org/journals/papers/tir/2020jul/fullPaper.pdf)

## Acknowledgments :heart:

Configuration setting are inspired by:

- [Lynis](https://github.com/CISOfy/Lynis)
- [Tiger](https://www.nongnu.org/tiger/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Mozilla SSL Configuration Generator](https://mozilla.github.io/server-side-tls/ssl-config-generator/)
- [OWASP ModSecurity Core Rule Set (CRS)](https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project)
- [Practical Apache, PHP-FPM & Nginx Reverse Proxy](http://ilovevirtualmin.com/practical-apache-php-fpm-nginx-reverse-proxy/)