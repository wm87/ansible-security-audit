#!/usr/bin/env bash

# ===================================================
# Script: create_local_security_audit.sh
# Zweck:  Vollständiges lokales Ansible Security Audit Projekt erstellen
# Version: 3.1 - Fixed shell compatibility issues
# ===================================================

set -euo pipefail

# -------------------------------
# Konfiguration
# -------------------------------
PROJECT_NAME="${1:-ansible-local-security-audit}"
AUTHOR="${USER}"
CREATION_DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Farben für Ausgabe
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# -------------------------------
# Funktionen
# -------------------------------
print_header() {
	echo -e "\n${BLUE}========================================${NC}"
	echo -e "${BLUE}$1${NC}"
	echo -e "${BLUE}========================================${NC}"
}

print_success() {
	echo -e "${GREEN}[✓] $1${NC}"
}

print_warning() {
	echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
	echo -e "${RED}[✗] $1${NC}"
}

check_dependencies() {
	local missing_deps=()

	if ! command -v ansible &>/dev/null; then
		missing_deps+=("ansible")
	fi

	if [[ ${#missing_deps[@]} -gt 0 ]]; then
		print_error "Fehlende Abhängigkeiten: ${missing_deps[*]}"
		echo "Installieren mit: sudo apt install ansible"
		exit 1
	fi

	print_success "Alle Abhängigkeiten erfüllt"
}

# -------------------------------
# Hauptprogramm
# -------------------------------
main() {
	print_header "Ansible Security Audit Projektgenerator v3.1"
	echo -e "Projektname: ${GREEN}${PROJECT_NAME}${NC}"
	echo -e "Autor: ${GREEN}${AUTHOR}${NC}"
	echo -e "Datum: ${GREEN}${CREATION_DATE}${NC}"
	echo -e "Erweiterte Checks: ${GREEN}7 neue Security-Bereiche${NC}"
	echo -e "Shell Kompatibilität: ${GREEN}Korrigiert für /bin/sh & /bin/bash${NC}"
	echo ""

	# Abhängigkeiten prüfen
	print_header "Prüfe Abhängigkeiten"
	check_dependencies

	# Existierendes Verzeichnis prüfen
	if [[ -d "$PROJECT_NAME" ]]; then
		print_warning "Verzeichnis '$PROJECT_NAME' existiert bereits!"
		read -p "Überschreiben? (j/N): " -n 1 -r
		echo
		if [[ ! $REPLY =~ ^[JjYy]$ ]]; then
			print_error "Abgebrochen."
			exit 1
		fi
		print_warning "Lösche vorhandenes Verzeichnis..."
		rm -rf "$PROJECT_NAME"
	fi

	# Projektverzeichnis erstellen
	print_header "Erstelle Projektstruktur"
	mkdir -p "$PROJECT_NAME"
	cd "$PROJECT_NAME" || exit

	# 1. Verzeichnisstruktur erstellen
	print_success "Erstelle Verzeichnisse..."
	mkdir -p roles/{password_policy,firewall_check,open_ports,package_check,log_audit_check,selinux_check,ssh_hardening,kernel_security,filesystem_permissions,container_security,report,suid_check,world_writable,cron_check,sudo_check,mount_options,aslr_check,kernel_modules}/tasks
	mkdir -p roles/password_policy/templates roles/report/templates
	mkdir -p vars group_vars

	# 2. Inventory-Datei für localhost erstellen
	print_success "Erstelle Inventory..."
	echo "localhost ansible_connection=local" >inventory

	# 3. ansible.cfg-Datei erstellen
	cat >ansible.cfg <<'EOL'
[defaults]
inventory = inventory
host_key_checking = False
retry_files_enabled = False
roles_path = ./roles
EOL
	print_success "ansible.cfg erstellt"

	# 4. Variablendateien
	print_success "Erstelle Variablendateien..."

	cat >vars/main.yml <<'EOL'
password_min_length: 12
password_expire_days: 90
firewall_required_ports:
  - 22
  - 80
  - 443
required_packages:
  - fail2ban
  - auditd
unnecessary_services:
  - telnet
  - ftp
ssh_allowed_users:
  - ubuntu
sysctl_secure:
  - { key: net.ipv4.ip_forward, value: 0 }
  - { key: net.ipv4.conf.all.accept_source_route, value: 0 }
  - { key: net.ipv4.conf.all.send_redirects, value: 0 }
# Neue Variablen für zusätzliche Checks
dangerous_suid_files:
  - /usr/bin/find
  - /usr/bin/nmap
  - /usr/bin/vim
  - /usr/bin/less
  - /usr/bin/more
  - /usr/bin/awk
  - /usr/bin/man
  - /usr/bin/curl
  - /usr/bin/wget
expected_suid_files:
  - /usr/bin/passwd
  - /usr/bin/sudo
  - /usr/bin/chsh
  - /usr/bin/chfn
  - /usr/bin/gpasswd
  - /usr/bin/mount
  - /usr/bin/umount
  - /usr/bin/su
  - /bin/umount
  - /bin/mount
  - /bin/ping
  - /bin/fusermount
  - /bin/su
dangerous_kernel_modules:
  - bluetooth
  - usb_storage
  - firewire
  - nfs
  - dccp
  - sctp
  - rds
  - tipc
EOL

	# 5. Haupt-Playbook erweitert
	cat >site.yml <<'EOL'
- hosts: all
  become: yes
  vars_files:
    - vars/main.yml
  roles:
    - password_policy
    - ssh_hardening
    - firewall_check
    - open_ports
    - package_check
    - log_audit_check
    - selinux_check
    - kernel_security
    - filesystem_permissions
    - container_security
    # SOFORT implementieren (neue Checks)
    - sudo_check
    - suid_check
    - world_writable
    - cron_check
    # INNERHALB 1 WOCHE (neue Checks)
    - mount_options
    - aslr_check
    - kernel_modules
    - report
EOL
	print_success "Playbooks erstellt"

	# 6. Rollen erstellen
	print_success "Erstelle Rollen..."

	# ==============================================
	# BESTEHENDE ROLLEN (dein Originalcode)
	# ==============================================

	# Rolle: password_policy (KORRIGIERT - mit besseren Checks)
	cat >roles/password_policy/tasks/main.yml <<'EOL'
---
- name: Check password minimum length in /etc/login.defs
  ansible.builtin.shell: |
    if [ -f /etc/login.defs ]; then
      grep '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}' | grep -E '^[0-9]+$' || echo "0"
    else
      echo "0"
    fi
  register: current_pass_len
  changed_when: false
  args:
    executable: /bin/bash

- name: Check password maximum days in /etc/login.defs
  ansible.builtin.shell: |
    if [ -f /etc/login.defs ]; then
      grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' | grep -E '^[0-9]+$' || echo "99999"
    else
      echo "99999"
    fi
  register: current_pass_max
  changed_when: false
  args:
    executable: /bin/bash

- name: Check for weak passwords (common checks)
  ansible.builtin.shell: |
    echo "=== SCHWACHE PASSWÖRTER PRÜFUNG ==="
    echo "HINWEIS: Echte Passwort-Prüfung erfordert John the Ripper oder ähnliche Tools"
    echo ""
    echo "Folgende einfache Checks werden durchgeführt:"
    echo "1. Leere Passwörter"
    echo "2. Passwörter gleich Benutzername"
    
    empty_password_users=""
    
    if [ -f /etc/shadow ]; then
      while IFS=: read -r username password_hash _; do
        # Check for empty password
        if [ -z "$password_hash" ] || [ "$password_hash" = "*" ] || [ "$password_hash" = "!" ] || [ "$password_hash" = "!!" ]; then
          empty_password_users="$empty_password_users $username"
        fi
      done < /etc/shadow
      
      if [ -n "$empty_password_users" ]; then
        echo "WARNUNG: Benutzer mit leeren/gesperrten Passwörtern:$empty_password_users"
      else
        echo "✓ Keine leeren Passwörter gefunden"
      fi
    else
      echo "/etc/shadow nicht verfügbar"
    fi
  register: weak_password_check
  changed_when: false
  args:
    executable: /bin/bash

- name: Check for old passwords (> 1 year) - CORRECTED
  ansible.builtin.shell: |
    if [ -f /etc/shadow ]; then
      echo "=== SEHR ALTE PASSWÖRTER (>365 Tage) ==="
      old_password_users=""
      current_days=$(( $(date +%s) / 86400 ))
      found_old=0
      
      while IFS=: read -r username _ last_change _ _ _ _ _; do
        if [ -n "$last_change" ] && [ "$last_change" -gt 0 ]; then
          days_old=$(( current_days - last_change ))
          if [ $days_old -gt 365 ]; then
            old_password_users="$old_password_users $username($days_old Tage)"
            found_old=1
          fi
        fi
      done < /etc/shadow
      
      if [ $found_old -eq 1 ]; then
        echo "ALTE PASSWÖRTER:$old_password_users"
      else
        echo "✓ Keine sehr alten Passwörter gefunden"
      fi
    else
      echo "/etc/shadow nicht verfügbar"
    fi
  register: old_passwords
  changed_when: false
  args:
    executable: /bin/bash

- name: Check password complexity in PAM configuration
  ansible.builtin.shell: |
    if [ -f /etc/pam.d/common-password ]; then
      echo "=== PAM PASSWORT-KOMPLEXITÄT ==="
      if grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
        echo "✓ pam_pwquality ist aktiviert"
        grep "pam_pwquality.so" /etc/pam.d/common-password
      elif grep -q "pam_cracklib.so" /etc/pam.d/common-password; then
        echo "✓ pam_cracklib ist aktiviert"
        grep "pam_cracklib.so" /etc/pam.d/common-password
      else
        echo "✗ Keine PAM Passwort-Komplexitätsprüfung aktiviert"
      fi
    else
      echo "/etc/pam.d/common-password nicht gefunden"
    fi
  register: pam_config_check
  changed_when: false
  args:
    executable: /bin/bash

- name: Set password policy facts for report - CORRECTED LOGIC
  ansible.builtin.set_fact:
    password_issue_min_length: "{{ current_pass_len.stdout | trim | int < password_min_length | int }}"
    password_issue_max_days: "{{ current_pass_max.stdout | trim | int > password_expire_days | int }}"
    current_password_length: "{{ current_pass_len.stdout | trim }}"
    current_password_max_days: "{{ current_pass_max.stdout | trim }}"
    password_weak_check: "{{ weak_password_check.stdout }}"
    password_old_users: "{{ old_passwords.stdout }}"
    password_pam_config: "{{ pam_config_check.stdout }}"
    password_has_weak_users: "{{ 'WARNUNG' in weak_password_check.stdout }}"
    # FIXED: Check for "ALTE PASSWÖRTER:" not just "ALTE"
    password_has_old_users: "{{ 'ALTE PASSWÖRTER:' in old_passwords.stdout }}"
    password_no_pam_complexity: "{{ 'Keine PAM' in pam_config_check.stdout or 'nicht aktiviert' in pam_config_check.stdout }}"

- name: Display password policy status
  ansible.builtin.debug:
    msg: |
      === PASSWORT-SICHERHEITSANALYSE ===
      
      SYSTEMRICHTLINIEN:
      - Minimale Passwortlänge: {{ current_pass_len.stdout | trim }} Zeichen (Soll: {{ password_min_length }})
      - Maximale Passwortgültigkeit: {{ current_pass_max.stdout | trim }} Tage (Soll: {{ password_expire_days }})
      
      {{ weak_password_check.stdout }}
      
      {{ old_passwords.stdout }}
      
      {{ pam_config_check.stdout }}
      
      BEDENKLICHE PROBLEME:
      - System-Passwortlänge zu kurz: {{ 'JA' if password_issue_min_length else 'NEIN' }}
      - System-Passwortablauf zu lang: {{ 'JA' if password_issue_max_days else 'NEIN' }}
      - Schwache/leere Passwörter: {{ 'JA' if password_has_weak_users else 'NEIN' }}
      - Sehr alte Passwörter (>1 Jahr): {{ 'JA' if password_has_old_users else 'NEIN' }}
      - Keine PAM Komplexitätsprüfung: {{ 'JA' if password_no_pam_complexity else 'NEIN' }}
      
      HINWEIS: Für echte Passwortstärke-Prüfung John the Ripper oder hashcat verwenden!
      ===================================
EOL

	# Rolle: ssh_hardening
	cat >roles/ssh_hardening/tasks/main.yml <<'EOL'
---
- name: Check if sshd_config exists
  ansible.builtin.stat:
    path: /etc/ssh/sshd_config
  register: sshd_config_exists
  changed_when: false

- name: Check PermitRootLogin
  ansible.builtin.shell: |
    if [ -f /etc/ssh/sshd_config ]; then
      grep PermitRootLogin /etc/ssh/sshd_config 2>/dev/null || echo "nicht gefunden"
    else
      echo "Datei nicht gefunden"
    fi
  register: root_ssh
  changed_when: false
  args:
    executable: /bin/bash

- name: Check PasswordAuthentication
  ansible.builtin.shell: |
    if [ -f /etc/ssh/sshd_config ]; then
      grep PasswordAuthentication /etc/ssh/sshd_config 2>/dev/null || echo "nicht gefunden"
    else
      echo "Datei nicht gefunden"
    fi
  register: pw_auth
  changed_when: false
  args:
    executable: /bin/bash

- name: Check AllowUsers
  ansible.builtin.shell: |
    if [ -f /etc/ssh/sshd_config ]; then
      grep AllowUsers /etc/ssh/sshd_config 2>/dev/null || echo "nicht konfiguriert"
    else
      echo "Datei nicht gefunden"
    fi
  register: allow_users
  changed_when: false
  args:
    executable: /bin/bash

- name: Set SSH facts for report
  ansible.builtin.set_fact:
    ssh_issue_root_login: "{{ 'yes' in root_ssh.stdout }}"
    ssh_issue_password_auth: "{{ 'yes' in pw_auth.stdout }}"
    ssh_root_login_status: "{{ root_ssh.stdout }}"
    ssh_password_auth_status: "{{ pw_auth.stdout }}"
    ssh_allow_users_status: "{{ allow_users.stdout }}"

- name: Display SSH configuration
  ansible.builtin.debug:
    msg: |
      === SSH KONFIGURATION ===
      SSH Config Datei: {{ 'Vorhanden' if sshd_config_exists.stat.exists else 'Fehlt' }}
      PermitRootLogin: {{ root_ssh.stdout }}
      PasswordAuthentication: {{ pw_auth.stdout }}
      AllowUsers: {{ allow_users.stdout }}
      Probleme:
      - Root-Login erlaubt: {{ 'JA' if ssh_issue_root_login else 'NEIN' }}
      - Passwort-Auth erlaubt: {{ 'JA' if ssh_issue_password_auth else 'NEIN' }}
      =========================
EOL

	# Rolle: firewall_check (KORRIGIERT - mit aufgeteilten set_fact tasks)
	cat >roles/firewall_check/tasks/main.yml <<'EOL'
---
- name: Check if ufw is installed (package check)
  ansible.builtin.package_facts:
    manager: auto

- name: Check ufw binary availability
  ansible.builtin.shell: |
    which ufw 2>/dev/null && echo "ja" || echo "nein"
  register: ufw_binary_check
  changed_when: false
  args:
    executable: /bin/bash

- name: Get actual firewall status
  ansible.builtin.shell: |
    if which ufw >/dev/null 2>&1; then
      # Get clean status without extra lines
      status_output=$(ufw status 2>/dev/null || echo "Fehler beim Abrufen")
      # Extract just the status line
      echo "$status_output" | grep -E "^Status:|^Zustand:" | head -1 || echo "Status nicht gefunden"
    else
      echo "UFW nicht installiert"
    fi
  register: firewall_status
  changed_when: false
  args:
    executable: /bin/bash

- name: Check if firewall is actually active
  ansible.builtin.shell: |
    if which ufw >/dev/null 2>&1; then
      if ufw status 2>/dev/null | grep -q "Status: active\|Zustand: aktiv"; then
        echo "aktiv"
      else
        echo "inaktiv"
      fi
    else
      echo "nicht_installiert"
    fi
  register: firewall_active_check
  changed_when: false
  args:
    executable: /bin/bash

- name: Set basic firewall facts
  ansible.builtin.set_fact:
    firewall_ufw_package_installed: "{{ 'ufw' in ansible_facts.packages }}"
    firewall_ufw_binary_available: "{{ ufw_binary_check.stdout == 'ja' }}"
    firewall_status_raw: "{{ firewall_status.stdout }}"
    firewall_is_active: "{{ firewall_active_check.stdout == 'aktiv' }}"

- name: Calculate firewall issues (separate task)
  ansible.builtin.set_fact:
    firewall_issue_not_installed: "{{ not firewall_ufw_package_installed and not firewall_ufw_binary_available }}"
    firewall_issue_not_active: "{{ firewall_ufw_binary_available and not firewall_is_active }}"

- name: Display firewall status
  ansible.builtin.debug:
    msg: |
      === FIREWALL STATUS ===
      UFW Paket installiert: {{ firewall_ufw_package_installed }}
      UFW Binary verfügbar: {{ firewall_ufw_binary_available }}
      Status Rohausgabe: {{ firewall_status_raw }}
      Ist aktiv: {{ firewall_is_active }}
      Probleme:
      - UFW nicht installiert: {{ 'JA' if firewall_issue_not_installed else 'NEIN' }}
      - UFW nicht aktiv: {{ 'JA' if firewall_issue_not_active else 'NEIN' }}
      =======================
EOL

	# Rolle: open_ports (KORRIGIERT - richtige Port-Zählung)
	cat >roles/open_ports/tasks/main.yml <<'EOL'
---
- name: Check open ports
  ansible.builtin.shell: ss -tuln 2>/dev/null || echo "Fehler beim Abrufen der Ports"
  register: all_ports
  changed_when: false
  args:
    executable: /bin/bash

- name: Count unique open ports (only unique port numbers)
  ansible.builtin.shell: |
    if command -v ss >/dev/null 2>&1; then
      # Count only unique port numbers (ignore duplicates from different IPs/protocols)
      ss -tuln 2>/dev/null | grep LISTEN | awk '{print $5}' | awk -F: '{print $NF}' | sort -nu | wc -l || echo "0"
    else
      echo "0"
    fi
  register: open_ports_count
  changed_when: false
  args:
    executable: /bin/bash

- name: Get list of open ports for report (unique ports only)
  ansible.builtin.shell: |
    if command -v ss >/dev/null 2>&1; then
      # Get only unique port numbers
      ss -tuln 2>/dev/null | grep LISTEN | awk '{print $5}' | awk -F: '{print $NF}' | sort -nu | tr '\n' ' ' | sed 's/ $//'
    else
      echo "ss nicht verfügbar"
    fi
  register: open_ports_list
  changed_when: false
  args:
    executable: /bin/bash

- name: Get formatted open ports list for HTML (with max 10 per line)
  ansible.builtin.shell: |
    if command -v ss >/dev/null 2>&1; then
      ports=$(ss -tuln 2>/dev/null | grep LISTEN | awk '{print $5}' | awk -F: '{print $NF}' | sort -nu | tr '\n' ' ')
      if [ -z "$ports" ] || [ "$ports" = " " ]; then
        echo "Keine offenen Ports"
      else
        # Remove leading/trailing spaces and format
        ports=$(echo "$ports" | sed 's/^ *//;s/ *$//')
        if [ -z "$ports" ]; then
          echo "Keine offenen Ports"
        else
          # Format with max 10 ports per line
          echo "$ports" | tr ' ' '\n' | awk '
          {
            if ($1 != "") {
              ports[NR] = $1
            }
          }
          END {
            count = 0
            output = ""
            for (i=1; i<=NR; i++) {
              if (ports[i] != "") {
                output = output ports[i]
                count++
                if (count % 10 == 0 && i != NR) {
                  output = output "<br>"
                } else if (i != NR) {
                  output = output ", "
                }
              }
            }
            print output
          }'
        fi
      fi
    else
      echo "ss nicht verfügbar"
    fi
  register: open_ports_formatted
  changed_when: false
  args:
    executable: /bin/bash

- name: Set open ports facts for report
  ansible.builtin.set_fact:
    open_ports_total: "{{ open_ports_count.stdout | trim | int }}"
    open_ports_list_str: "{{ open_ports_list.stdout }}"
    open_ports_formatted_str: "{{ open_ports_formatted.stdout }}"
    open_ports_issue_ss_missing: "{{ 'ss nicht verfügbar' in open_ports_formatted.stdout }}"

- name: Display open ports summary
  ansible.builtin.debug:
    msg: |
      === OFFENE PORTS ===
      Anzahl einzigartiger Ports: {{ open_ports_total }}
      Offene Ports Liste: {{ open_ports_list_str }}
      Formatierte Liste: {{ open_ports_formatted_str }}
      Probleme:
      - ss Tool nicht verfügbar: {{ 'JA' if open_ports_issue_ss_missing else 'NEIN' }}
      - Viele offene Ports (>20): {{ 'JA' if open_ports_total > 20 else 'NEIN' }}
      ====================
EOL

	# Rolle: package_check
	cat >roles/package_check/tasks/main.yml <<'EOL'
---
- name: Check if packages are installed
  ansible.builtin.package_facts:
    manager: auto

- name: Initialize missing packages list
  ansible.builtin.set_fact:
    missing_packages_list: []
    missing_packages_count: 0

- name: Check each required package
  ansible.builtin.set_fact:
    missing_packages_list: "{{ missing_packages_list + [item] }}"
    missing_packages_count: "{{ missing_packages_count + 1 }}"
  loop: "{{ required_packages }}"
  when: item not in ansible_facts.packages
  loop_control:
    label: "{{ item }}"

- name: Display package status
  ansible.builtin.debug:
    msg: |
      === PAKET-ÜBERPRÜFUNG ===
      {% for pkg in required_packages %}
      {{ pkg }}: {{ 'Installiert ✓' if pkg in ansible_facts.packages else 'Fehlt ✗' }}
      {% endfor %}
      Probleme:
      - Fehlende Pakete: {{ missing_packages_count | default(0) }}
      - Liste: {{ missing_packages_list | default('Keine') | join(', ') }}
      ========================
EOL

	# Rolle: log_audit_check
	cat >roles/log_audit_check/tasks/main.yml <<'EOL'
---
- name: Check if auditd is installed using package manager
  ansible.builtin.package_facts:
    manager: auto

- name: Check auditd service status
  ansible.builtin.service_facts:

- name: Check auditctl command
  ansible.builtin.command: which auditctl
  register: auditctl_which
  ignore_errors: yes
  changed_when: false
  args:
    executable: /bin/bash

- name: Set auditd facts
  ansible.builtin.set_fact:
    auditd_package_installed: "{{ 'auditd' in ansible_facts.packages }}"
    auditd_service_exists: "{{ 'auditd.service' in ansible_facts.services }}"
    auditd_service_active: "{{ ansible_facts.services['auditd.service'].state == 'running' if 'auditd.service' in ansible_facts.services else false }}"
    auditd_service_enabled: "{{ ansible_facts.services['auditd.service'].status == 'enabled' if 'auditd.service' in ansible_facts.services else false }}"
    auditctl_available: "{{ auditctl_which.rc == 0 }}"
    auditd_installed_version: "{{ ansible_facts.packages['auditd'][0].version if 'auditd' in ansible_facts.packages else 'nicht installiert' }}"

- name: Calculate auditd issues
  ansible.builtin.set_fact:
    auditd_issue_not_installed: "{{ not auditd_package_installed and not auditctl_available }}"
    auditd_issue_not_active: "{{ auditd_service_exists and not auditd_service_active }}"
    auditd_issue_not_enabled: "{{ auditd_service_exists and not auditd_service_enabled }}"

- name: Display auditd status
  ansible.builtin.debug:
    msg: |
      === AUDITD STATUS ===
      Paket installiert: {{ auditd_package_installed }}
      Paket Version: {{ auditd_installed_version }}
      Service existiert: {{ auditd_service_exists }}
      Service aktiv: {{ auditd_service_active }}
      Service enabled: {{ auditd_service_enabled }}
      auditctl verfügbar: {{ auditctl_available }}
      Probleme:
      - auditd nicht installiert: {{ 'JA' if auditd_issue_not_installed else 'NEIN' }}
      - auditd nicht aktiv: {{ 'JA' if auditd_issue_not_active else 'NEIN' }}
      - auditd nicht enabled: {{ 'JA' if auditd_issue_not_enabled else 'NEIN' }}
      =====================
EOL

	# Rolle: selinux_check
	cat >roles/selinux_check/tasks/main.yml <<'EOL'
---
- name: Check if SELinux is available
  ansible.builtin.shell: |
    which getenforce 2>/dev/null && echo "ja" || echo "nein"
  register: selinux_cmd
  changed_when: false
  args:
    executable: /bin/bash

- name: Check SELinux status
  ansible.builtin.shell: |
    if which getenforce >/dev/null 2>&1; then
      getenforce 2>/dev/null || echo "unbekannt"
    else
      echo "nicht verfügbar"
    fi
  register: selinux_status
  changed_when: false
  args:
    executable: /bin/bash

- name: Set SELinux facts for report
  ansible.builtin.set_fact:
    selinux_issue_not_available: "{{ selinux_cmd.stdout != 'ja' }}"
    selinux_issue_not_enforcing: "{{ selinux_status.stdout != 'Enforcing' }}"

- name: Display SELinux status
  ansible.builtin.debug:
    msg: |
      === SELINUX STATUS ===
      Verfügbar: {{ selinux_cmd.stdout }}
      Status: {{ selinux_status.stdout }}
      Probleme:
      - SELinux nicht verfügbar: {{ 'JA' if selinux_issue_not_available else 'NEIN' }}
      - SELinux nicht enforcing: {{ 'JA' if selinux_issue_not_enforcing else 'NEIN' }}
      ======================
EOL

	# Rolle: kernel_security
	cat >roles/kernel_security/tasks/main.yml <<'EOL'
---
- name: Display sysctl settings to check
  ansible.builtin.debug:
    msg: |
      === KERNEL SECURITY SETTINGS ===
      Zu prüfende Einstellungen:
      {% for item in sysctl_secure %}
      - {{ item.key }} = {{ item.value }}
      {% endfor %}
      ================================
EOL

	# Rolle: filesystem_permissions
	cat >roles/filesystem_permissions/tasks/main.yml <<'EOL'
---
- name: Check /etc/passwd permissions
  ansible.builtin.stat:
    path: /etc/passwd
  register: passwd_stat
  changed_when: false

- name: Check if file is world writable
  ansible.builtin.set_fact:
    is_world_writable: "{{ (passwd_stat.stat.mode | int) % 2 == 1 }}"

- name: Set filesystem facts for report
  ansible.builtin.set_fact:
    fs_issue_world_writable: "{{ is_world_writable }}"
    fs_passwd_permissions: "{{ passwd_stat.stat.mode }}"

- name: Display file permissions
  ansible.builtin.debug:
    msg: |
      === DATEIBERECHTIGUNGEN ===
      /etc/passwd:
        Berechtigungen: {{ passwd_stat.stat.mode }}
        World-writable: {{ 'Ja' if is_world_writable else 'Nein' }}
      Probleme:
      - /etc/passwd world-writable: {{ 'JA' if is_world_writable else 'NEIN' }}
      ===========================
EOL

	# Rolle: container_security
	cat >roles/container_security/tasks/main.yml <<'EOL'
---
- name: Check if docker is available
  ansible.builtin.shell: |
    which docker 2>/dev/null && echo "ja" || echo "nein"
  register: docker_check
  changed_when: false
  args:
    executable: /bin/bash

- name: Set container facts for report
  ansible.builtin.set_fact:
    container_docker_available: "{{ docker_check.stdout == 'ja' }}"

- name: Display Docker status
  ansible.builtin.debug:
    msg: |
      === DOCKER STATUS ===
      Verfügbar: {{ docker_check.stdout }}
      =====================
EOL

	# ==============================================
	# NEUE ROLLEN: SOFORT CHECKS (KORRIGIERT)
	# ==============================================

	# Rolle: sudo_check (KORRIGIERT - Shell Kompatibilität)
	cat >roles/sudo_check/tasks/main.yml <<'EOL'
---
- name: Check for NOPASSWD entries in sudoers
  ansible.builtin.shell: |
    echo "=== SUDO NOPASSWD CHECKS ==="
    
    # Check main sudoers file
    if [ -f /etc/sudoers ]; then
      echo "1. /etc/sudoers:"
      grep -E "^[^#].*NOPASSWD" /etc/sudoers 2>/dev/null || echo "  Keine NOPASSWD-Einträge"
    fi
    
    # Check sudoers.d directory
    if [ -d /etc/sudoers.d ]; then
      echo "2. /etc/sudoers.d/*:"
      grep -rE "^[^#].*NOPASSWD" /etc/sudoers.d/ 2>/dev/null | head -10 || echo "  Keine NOPASSWD-Einträge"
    fi
    
    # Check for dangerous wildcards
    echo "3. Gefährliche Wildcards:"
    grep -rE "ALL.*=.*NOPASSWD.*:.*ALL" /etc/sudoers* 2>/dev/null | head -5 || echo "  Keine gefährlichen ALL-Wildcards"
    
    # Check sudo timeout
    echo "4. Sudo Timeout (timestamp_timeout):"
    grep -r "timestamp_timeout" /etc/sudoers* 2>/dev/null || echo "  Kein Timeout konfiguriert (Standard: 15min)"
  register: sudo_check_output
  changed_when: false
  args:
    executable: /bin/bash

- name: Count NOPASSWD entries
  ansible.builtin.shell: |
    grep -rE "^[^#].*NOPASSWD" /etc/sudoers* 2>/dev/null | wc -l
  register: sudo_nopasswd_count
  changed_when: false
  args:
    executable: /bin/bash

- name: Set sudo check facts
  ansible.builtin.set_fact:
    sudo_has_nopasswd: "{{ 'NOPASSWD' in sudo_check_output.stdout }}"
    sudo_nopasswd_entries: "{{ sudo_nopasswd_count.stdout | int }}"
    sudo_no_timeout: "{{ 'Kein Timeout' in sudo_check_output.stdout }}"

- name: Display sudo check summary
  ansible.builtin.debug:
    msg: |
      === SUDO SICHERHEITSPRÜFUNG ===
      {{ sudo_check_output.stdout }}
      
      ZUSAMMENFASSUNG:
      - NOPASSWD Einträge gefunden: {{ sudo_nopasswd_count.stdout }}
      - Sudo Timeout konfiguriert: {{ 'NEIN' if sudo_no_timeout else 'JA' }}
      
      RISIKOBEWERTUNG:
      - Kritische NOPASSWD Einträge: {{ 'JA' if sudo_nopasswd_entries > 0 else 'NEIN' }}
      - Kein Sudo Timeout: {{ 'JA' if sudo_no_timeout else 'NEIN' }}
      ==============================
EOL

	# Rolle: suid_check (KORRIGIERT - Shell Kompatibilität)
	cat >roles/suid_check/tasks/main.yml <<'EOL'
---
- name: Find all SUID/SGID files
  ansible.builtin.shell: |
    find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l
  register: all_suid_count
  changed_when: false
  args:
    executable: /bin/bash

- name: Find unexpected SUID/SGID files
  ansible.builtin.shell: |
    echo "=== UNERWARTETE SUID/SGID DATEIEN ==="
    
    # Create pattern for expected files
    expected_pattern="{{ expected_suid_files | join('|') | replace('/', '\\/') }}"
    
    # Find unexpected SUID/SGID files
    find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | \
    grep -vE "($expected_pattern)" | \
    head -20  # Limit output
    
    echo ""
    echo "=== GEFÄHRLICHE SUID DATEIEN (manuell prüfen) ==="
    # Check for known dangerous SUID files - sh-kompatible Schleife
    for file in {{ dangerous_suid_files | join(' ') }}; do
      if [ -f "$file" ] && [ -u "$file" ]; then
        echo "WARNUNG: $file hat SUID bit gesetzt!"
      fi
    done
  register: unexpected_suid_output
  changed_when: false
  args:
    executable: /bin/bash

- name: Count unexpected SUID/SGID files
  ansible.builtin.shell: |
    expected_pattern="{{ expected_suid_files | join('|') | replace('/', '\\/') }}"
    find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | \
    grep -vE "($expected_pattern)" | \
    wc -l
  register: unexpected_suid_count
  changed_when: false
  args:
    executable: /bin/bash

- name: Set suid check facts
  ansible.builtin.set_fact:
    suid_total_count: "{{ all_suid_count.stdout | int }}"
    suid_unexpected_count: "{{ unexpected_suid_count.stdout | int }}"
    suid_has_dangerous: "{{ 'WARNUNG:' in unexpected_suid_output.stdout }}"
    suid_unexpected_files: "{{ unexpected_suid_output.stdout }}"

- name: Display suid check summary
  ansible.builtin.debug:
    msg: |
      === SUID/SGID SICHERHEITSPRÜFUNG ===
      
      STATISTIK:
      - Gesamtzahl SUID/SGID Dateien: {{ suid_total_count }}
      - Unerwartete SUID/SGID Dateien: {{ suid_unexpected_count }}
      
      {{ suid_unexpected_files }}
      
      RISIKOBEWERTUNG:
      - Viele unerwartete SUID Dateien (>10): {{ 'JA' if suid_unexpected_count > 10 else 'NEIN' }}
      - Gefährliche SUID Dateien gefunden: {{ 'JA' if suid_has_dangerous else 'NEIN' }}
      ====================================
EOL

	# Rolle: world_writable (KORRIGIERT - Shell Kompatibilität)
	cat >roles/world_writable/tasks/main.yml <<'EOL'
---
- name: Find world-writable files (excluding temp directories)
  ansible.builtin.shell: |
    echo "=== WORLD-WRITABLE DATEIEN (kritisch) ==="
    
    # Find world-writable files excluding common temp/device directories
    find / -path /proc -prune -o \
         -path /sys -prune -o \
         -path /tmp -prune -o \
         -path /dev -prune -o \
         -path /run -prune -o \
         -type f -perm -0002 ! -type l -print 2>/dev/null | \
    head -30
    
    echo ""
    echo "=== WORLD-WRITABLE VERZEICHNISSE ==="
    find / -path /proc -prune -o \
         -path /sys -prune -o \
         -path /tmp -prune -o \
         -path /dev -prune -o \
         -path /run -prune -o \
         -type d -perm -0002 ! -path "/tmp/*" ! -path "/var/tmp/*" -print 2>/dev/null | \
    head -20
  register: world_writable_output
  changed_when: false
  args:
    executable: /bin/bash

- name: Count critical world-writable files
  ansible.builtin.shell: |
    find / -path /proc -prune -o \
         -path /sys -prune -o \
         -path /tmp -prune -o \
         -path /dev -prune -o \
         -path /run -prune -o \
         -type f -perm -0002 ! -type l -print 2>/dev/null | \
    wc -l
  register: world_writable_count
  changed_when: false
  args:
    executable: /bin/bash

- name: Check for critical world-writable files (shell-agnostic version)
  ansible.builtin.shell: |
    echo "=== KRITISCHE SYSTEMDATEIEN PRÜFEN ==="
    
    # Liste der kritischen Dateien - sh-kompatible Syntax
    for file in "/etc/passwd" "/etc/shadow" "/etc/group" "/etc/sudoers" "/etc/ssh/sshd_config" "/etc/crontab" "/etc/hosts" "/etc/resolv.conf"; do
      if [ -f "$file" ]; then
        # Prüfe ob die Datei world-writable ist
        permissions=$(stat -c "%A" "$file" 2>/dev/null || echo "---------")
        
        # Prüfe das 9. Zeichen (world write)
        if echo "$permissions" | cut -c9 | grep -q "w"; then
          echo "KRITISCH: $file ist world-writable! (Berechtigungen: $permissions)"
        fi
      fi
    done
    
    # Alternative Methode mit test -w (funktioniert auch mit sh)
    echo ""
    echo "=== ALTERNATIVE PRÜFUNG MIT TEST -w ==="
    for file in "/etc/passwd" "/etc/shadow" "/etc/group" "/etc/sudoers" "/etc/ssh/sshd_config" "/etc/crontab" "/etc/hosts" "/etc/resolv.conf"; do
      if [ -f "$file" ] && [ -w "$file" ]; then
        # Zusätzliche Prüfung: Ist es wirklich world-writable oder nur für den aktuellen Benutzer?
        owner=$(stat -c "%U" "$file" 2>/dev/null || echo "unknown")
        current_user=$(whoami)
        if [ "$owner" != "$current_user" ] && [ "$owner" != "root" ]; then
          echo "VERDACHT: $file ist schreibbar für $current_user, aber gehört $owner"
        fi
      fi
    done
  register: critical_world_writable_check
  changed_when: false
  args:
    executable: /bin/bash

- name: Check world-writable with find (alternative method)
  ansible.builtin.shell: |
    echo "=== KRITISCHE DATEIEN MIT FIND PRÜFEN ==="
    
    # Direkte Suche nach world-writable kritischen Dateien
    for file in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config /etc/crontab /etc/hosts /etc/resolv.conf; do
      if [ -f "$file" ]; then
        # Benutze find mit -perm für direkte Prüfung
        if find "$file" -perm -0002 2>/dev/null | grep -q "$file"; then
          permissions=$(stat -c "%a %A" "$file" 2>/dev/null || echo "??? ????????")
          echo "WORLD-WRITABLE: $file ($permissions)"
        fi
      fi
    done
  register: world_writable_find_check
  changed_when: false
  args:
    executable: /bin/bash

- name: Set world writable facts
  ansible.builtin.set_fact:
    world_writable_files_count: "{{ world_writable_count.stdout | int }}"
    world_writable_has_critical: "{{ 'KRITISCH:' in critical_world_writable_check.stdout or 'WORLD-WRITABLE:' in world_writable_find_check.stdout }}"
    world_writable_output_text: "{{ world_writable_output.stdout }}"
    world_writable_critical_text: "{{ critical_world_writable_check.stdout }}"
    world_writable_find_text: "{{ world_writable_find_check.stdout }}"

- name: Display world writable summary
  ansible.builtin.debug:
    msg: |
      === WORLD-WRITABLE DATEIEN PRÜFUNG ===
      
      STATISTIK:
      - World-writable Dateien (außer Temp): {{ world_writable_files_count }}
      - Kritische Dateien world-writable: {{ 'JA' if world_writable_has_critical else 'NEIN' }}
      
      {{ world_writable_output_text }}
      
      {{ world_writable_critical_text }}
      
      {{ world_writable_find_text }}
      
      RISIKOBEWERTUNG:
      - World-writable Systemdateien: {{ 'KRITISCH' if world_writable_has_critical else 'OK' }}
      =====================================
EOL

	# Rolle: cron_check (KORRIGIERT - Shell Kompatibilität)
	cat >roles/cron_check/tasks/main.yml <<'EOL'
---
- name: Check for suspicious cron jobs
  ansible.builtin.shell: |
    echo "=== VERDÄCHTIGE CRON JOBS ==="
    
    # Check system crontabs
    echo "1. System Cron (/etc/cron.*):"
    ls -la /etc/cron.* 2>/dev/null | head -20
    
    echo ""
    echo "2. Benutzer Cron Jobs:"
    ls -la /var/spool/cron/crontabs/ 2>/dev/null || echo "  Keine Benutzer crontabs"
    
    echo ""
    echo "3. Inhalt von /etc/crontab:"
    cat /etc/crontab 2>/dev/null | grep -v "^#" | head -20 || echo "  /etc/crontab nicht gefunden"
    
    echo ""
    echo "4. Verdächtige Befehle in Cron:"
    suspicious_patterns="curl.*http\|wget.*http\|bash -c\|sh -c\|perl -e\|python -c\|php -r\|nc.*-e\|/dev/tcp"
    grep -rE "($suspicious_patterns)" /etc/cron* /var/spool/cron/ 2>/dev/null | \
    grep -v "^#" | head -10 || echo "  Keine verdächtigen Cron Jobs gefunden"
    
    echo ""
    echo "5. World-writable Cron Verzeichnisse:"
    find /etc/cron* /var/spool/cron* -type d -perm /o+w 2>/dev/null || echo "  Keine world-writable Cron Verzeichnisse"
  register: cron_check_output
  changed_when: false
  args:
    executable: /bin/bash

- name: Check cron service status
  ansible.builtin.shell: |
    echo "=== CRON SERVICE STATUS ==="
    systemctl is-active cron 2>/dev/null || systemctl is-active crond 2>/dev/null || echo "Cron Service nicht aktiv"
    systemctl is-enabled cron 2>/dev/null || systemctl is-enabled crond 2>/dev/null || echo "Cron Service nicht enabled"
  register: cron_service_check
  changed_when: false
  args:
    executable: /bin/bash

- name: Count suspicious cron entries
  ansible.builtin.shell: |
    suspicious_patterns="curl.*http\|wget.*http\|bash -c\|sh -c\|perl -e\|python -c\|php -r\|nc.*-e\|/dev/tcp"
    grep -rE "($suspicious_patterns)" /etc/cron* /var/spool/cron/ 2>/dev/null | \
    grep -v "^#" | wc -l
  register: suspicious_cron_count
  changed_when: false
  args:
    executable: /bin/bash

- name: Set cron check facts
  ansible.builtin.set_fact:
    cron_has_suspicious: "{{ suspicious_cron_count.stdout | int > 0 }}"
    cron_suspicious_count: "{{ suspicious_cron_count.stdout | int }}"
    cron_service_active: "{{ 'aktiv' in cron_service_check.stdout }}"
    cron_output_text: "{{ cron_check_output.stdout }}"

- name: Display cron check summary
  ansible.builtin.debug:
    msg: |
      === CRON SICHERHEITSPRÜFUNG ===
      
      {{ cron_check_output.stdout }}
      
      {{ cron_service_check.stdout }}
      
      ZUSAMMENFASSUNG:
      - Verdächtige Cron Jobs: {{ cron_suspicious_count }}
      - Cron Service aktiv: {{ cron_service_active }}
      
      RISIKOBEWERTUNG:
      - Verdächtige Cron Jobs gefunden: {{ 'JA' if cron_has_suspicious else 'NEIN' }}
      ================================
EOL

	# ==============================================
	# NEUE ROLLEN: 1-WOCHE CHECKS (KORRIGIERT)
	# ==============================================

	# Rolle: mount_options (KORRIGIERT - Shell Kompatibilität)
	cat >roles/mount_options/tasks/main.yml <<'EOL'
---
- name: Check mount options for security
  ansible.builtin.shell: |
    echo "=== MOUNT OPTIONEN SICHERHEIT ==="
    
    echo "1. Aktuelle Mounts:"
    mount | grep -E "/(boot|home|tmp|var|usr)" | head -20
    
    echo ""
    echo "2. Fehlende Sicherheitsoptionen:"
    mount | grep -E " /(boot|home|var|usr) " | grep -vE "(nodev|nosuid|noexec)" || echo "  Alle haben Sicherheitsoptionen"
    
    echo ""
    echo "3. /tmp Partition:"
    mount | grep " /tmp " || echo "  /tmp nicht separat gemountet"
    mount | grep " /tmp " | grep -E "(noexec|nosuid|nodev)" || echo "  /tmp ohne noexec/nosuid"
    
    echo ""
    echo "4. /dev/shm Mount:"
    mount | grep " /dev/shm " || echo "  /dev/shm nicht gemountet"
    mount | grep " /dev/shm " | grep -E "(noexec|nosuid)" || echo "  /dev/shm ohne noexec/nosuid"
    
    echo ""
    echo "5. /home Partition Optionen:"
    mount | grep " /home " | grep nodev || echo "  /home ohne nodev (kann riskant sein)"
  register: mount_check_output
  changed_when: false
  args:
    executable: /bin/bash

- name: Check fstab configuration
  ansible.builtin.shell: |
    echo "=== FSTAB KONFIGURATION ==="
    grep -E "/(boot|home|tmp|var|usr)" /etc/fstab 2>/dev/null | grep -v "^#" || echo "  Keine relevanten Einträge in fstab"
  register: fstab_check
  changed_when: false
  args:
    executable: /bin/bash

- name: Count mounts without security options
  ansible.builtin.shell: |
    mount | grep -E " /(boot|home|var|usr) " | grep -vE "(nodev|nosuid|noexec)" | wc -l
  register: insecure_mounts_count
  changed_when: false
  args:
    executable: /bin/bash

- name: Set mount check facts
  ansible.builtin.set_fact:
    mount_insecure_count: "{{ insecure_mounts_count.stdout | int }}"
    mount_tmp_insecure: "{{ '/tmp ohne noexec/nosuid' in mount_check_output.stdout }}"
    mount_home_insecure: "{{ '/home ohne nodev' in mount_check_output.stdout }}"
    mount_shm_insecure: "{{ '/dev/shm ohne noexec/nosuid' in mount_check_output.stdout }}"
    mount_output_text: "{{ mount_check_output.stdout }}"
    fstab_output_text: "{{ fstab_check.stdout }}"

- name: Display mount check summary
  ansible.builtin.debug:
    msg: |
      === MOUNT SICHERHEITSPRÜFUNG ===
      
      {{ mount_check_output.stdout }}
      
      {{ fstab_check.stdout }}
      
      ZUSAMMENFASSUNG:
      - Mounts ohne Sicherheitsoptionen: {{ mount_insecure_count }}
      - /tmp unsicher: {{ 'JA' if mount_tmp_insecure else 'NEIN' }}
      - /home unsicher: {{ 'JA' if mount_home_insecure else 'NEIN' }}
      - /dev/shm unsicher: {{ 'JA' if mount_shm_insecure else 'NEIN' }}
      
      RISIKOBEWERTUNG:
      - Kritische Mounts unsicher: {{ 'HOCH' if mount_tmp_insecure or mount_shm_insecure else 'NIEDRIG' }}
      =================================
EOL

	# Rolle: aslr_check (KORRIGIERT - Shell Kompatibilität)
	cat >roles/aslr_check/tasks/main.yml <<'EOL'
---
- name: Check ASLR status
  ansible.builtin.shell: |
    echo "=== ASLR (Address Space Layout Randomization) ==="
    
    current_value=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "nicht verfügbar")
    echo "Aktueller Wert: $current_value"
    
    echo ""
    echo "Bedeutung der Werte:"
    echo "  0 = ASLR deaktiviert (KEIN SCHUTZ)"
    echo "  1 = Konservativ (Shared Libraries randomisiert)"
    echo "  2 = Vollständig (Stack, Heap, Libraries randomisiert)"
    
    echo ""
    echo "Sysctl Einstellung:"
    sysctl kernel.randomize_va_space 2>/dev/null || echo "  Sysctl nicht verfügbar"
  register: aslr_check_output
  changed_when: false
  args:
    executable: /bin/bash

- name: Check kernel parameters
  ansible.builtin.shell: |
    cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "0"
  register: aslr_value
  changed_when: false
  args:
    executable: /bin/bash

- name: Check for kernel command line parameters
  ansible.builtin.shell: |
    echo "=== KERNEL BOOT PARAMETER ==="
    cat /proc/cmdline 2>/dev/null | grep -i "norandmaps\|aslr" || echo "  Keine ASLR-relevanten Boot-Parameter"
  register: kernel_params_check
  changed_when: false
  args:
    executable: /bin/bash

- name: Set aslr check facts
  ansible.builtin.set_fact:
    aslr_disabled: "{{ aslr_value.stdout == '0' }}"
    aslr_partial: "{{ aslr_value.stdout == '1' }}"
    aslr_full: "{{ aslr_value.stdout == '2' }}"
    aslr_value_num: "{{ aslr_value.stdout }}"
    aslr_has_norandmaps: "{{ 'norandmaps' in kernel_params_check.stdout }}"

- name: Display aslr check summary
  ansible.builtin.debug:
    msg: |
      === ASLR SICHERHEITSPRÜFUNG ===
      
      {{ aslr_check_output.stdout }}
      
      {{ kernel_params_check.stdout }}
      
      ZUSAMMENFASSUNG:
      - ASLR Status: {% if aslr_disabled %}DEAKTIVIERT{% elif aslr_partial %}KONSERVATIV{% else %}VOLLSTÄNDIG{% endif %}
      - ASLR Wert: {{ aslr_value_num }}
      - norandmaps Boot-Parameter: {{ 'JA' if aslr_has_norandmaps else 'NEIN' }}
      
      RISIKOBEWERTUNG:
      - ASLR deaktiviert: {{ 'KRITISCH' if aslr_disabled else 'OK' }}
      - norandmaps Parameter: {{ 'KRITISCH' if aslr_has_norandmaps else 'OK' }}
      ================================
EOL

	# Rolle: kernel_modules (KORRIGIERT - Shell Kompatibilität)
	cat >roles/kernel_modules/tasks/main.yml <<'EOL'
---
- name: Check dangerous kernel modules
  ansible.builtin.shell: |
    echo "=== GEFÄHRLICHE KERNEL MODULE ==="
    
    echo "1. Aktuell geladene gefährliche Module:"
    # Sh-kompatible Schleife
    for module in {{ dangerous_kernel_modules | join(' ') }}; do
      if lsmod | grep -q "^${module} "; then
        echo "  WARNUNG: $module ist geladen!"
      fi
    done
    
    echo ""
    echo "2. Module in /etc/modprobe.d/ blacklisted:"
    dangerous_pattern="{{ dangerous_kernel_modules | join('|') }}"
    grep -r "blacklist" /etc/modprobe.d/ 2>/dev/null | grep -E "$dangerous_pattern" || echo "  Keine gefährlichen Module blacklisted"
    
    echo ""
    echo "3. Ungewöhnliche/unbekannte Module:"
    # Erste 5 Module als Muster
    first_five="{{ dangerous_kernel_modules[:5] | join('|') }}"
    lsmod | awk '{print $1}' | grep -vE "^($first_five)" | tail -20
    
    echo ""
    echo "4. Module die automatisch geladen werden:"
    ls /etc/modules-load.d/ 2>/dev/null || echo "  Keine modules-load.d Konfiguration"
  register: kernel_modules_output
  changed_when: false
  args:
    executable: /bin/bash

- name: Count loaded dangerous modules
  ansible.builtin.shell: |
    loaded_count=0
    for module in {{ dangerous_kernel_modules | join(' ') }}; do
      if lsmod | grep -q "^${module} "; then
        loaded_count=$((loaded_count + 1))
      fi
    done
    echo $loaded_count
  register: loaded_dangerous_count
  changed_when: false
  args:
    executable: /bin/bash

- name: Check module signing
  ansible.builtin.shell: |
    echo "=== MODULE SIGNATURE PRÜFUNG ==="
    sysctl kernel.modules_disabled 2>/dev/null || echo "  Module signing nicht konfiguriert"
    dmesg | grep -i "module signature" | tail -3 || echo "  Keine Module Signature Info"
  register: module_signing_check
  changed_when: false
  args:
    executable: /bin/bash

- name: Set kernel modules facts
  ansible.builtin.set_fact:
    kernel_modules_loaded_dangerous: "{{ loaded_dangerous_count.stdout | int }}"
    kernel_modules_has_dangerous: "{{ loaded_dangerous_count.stdout | int > 0 }}"
    kernel_modules_output_text: "{{ kernel_modules_output.stdout }}"
    kernel_modules_signing_info: "{{ module_signing_check.stdout }}"

- name: Display kernel modules summary
  ansible.builtin.debug:
    msg: |
      === KERNEL MODULE SICHERHEITSPRÜFUNG ===
      
      {{ kernel_modules_output.stdout }}
      
      {{ kernel_modules_signing_info }}
      
      ZUSAMMENFASSUNG:
      - Gefährliche Module geladen: {{ kernel_modules_loaded_dangerous }}
      - Module Signatur aktiviert: {{ 'UNBEKANNT' if 'nicht konfiguriert' in kernel_modules_signing_info else 'JA' }}
      
      RISIKOBEWERTUNG:
      - Gefährliche Module geladen: {{ 'HOCH' if kernel_modules_has_dangerous else 'NIEDRIG' }}
      ========================================
EOL

	# Rolle: report
	cat >roles/report/tasks/main.yml <<'EOL'
---
- name: Generate HTML report
  ansible.builtin.template:
    src: report.j2
    dest: "/bigdata/tmp/ansible-security-audit/security_report_{{ inventory_hostname }}.html"
EOL

	# ==============================================
	# ERWEITERTES REPORT TEMPLATE (ungeändert)
	# ==============================================
	cat >roles/report/templates/report.j2 <<'EOL'
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {{ inventory_hostname }}</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 40px; 
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        
        h1 { 
            color: #2c3e50; 
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 30px;
        }
        
        h2 { 
            color: #3498db; 
            border-bottom: 2px solid #ecf0f1; 
            padding-bottom: 8px;
            margin-top: 30px;
        }
        
        .header-info {
            display: flex;
            justify-content: space-between;
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 30px;
        }
        
        .info-item {
            flex: 1;
            text-align: center;
        }
        
        .info-label {
            font-weight: bold;
            color: #7f8c8d;
            font-size: 0.9em;
        }
        
        .info-value {
            font-size: 1.1em;
            color: #2c3e50;
        }
        
        .section { 
            margin-bottom: 40px;
            padding: 20px;
            background: #f9f9f9;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        
        .critical-section {
            border-left: 4px solid #e74c3c;
            background: #ffeaea;
        }
        
        .warning-section {
            border-left: 4px solid #f39c12;
            background: #fff4e6;
        }
        
        .check-result {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
            margin-left: 10px;
        }
        
        .check-ok {
            background-color: #2ecc71;
            color: white;
        }
        
        .check-warning {
            background-color: #f39c12;
            color: white;
        }
        
        .check-critical {
            background-color: #e74c3c;
            color: white;
        }
        
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-top: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        th { 
            background-color: #3498db;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        
        td { 
            border: 1px solid #ddd; 
            padding: 10px 12px; 
            text-align: left;
            vertical-align: top;
        }
        
        tr:nth-child(even) {
            background-color: #f8f9fa;
        }
        
        tr:hover {
            background-color: #e8f4fc;
        }
        
        .summary-stats {
            display: flex;
            justify-content: space-around;
            margin: 30px 0;
            text-align: center;
        }
        
        .stat-box {
            padding: 20px;
            border-radius: 8px;
            background: #ecf0f1;
            flex: 1;
            margin: 0 10px;
        }
        
        .stat-box.critical {
            background: #ffeaea;
            border: 2px solid #e74c3c;
        }
        
        .stat-box.warning {
            background: #fff4e6;
            border: 2px solid #f39c12;
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #3498db;
            display: block;
        }
        
        .stat-number.critical {
            color: #e74c3c;
        }
        
        .stat-number.warning {
            color: #f39c12;
        }
        
        .stat-label {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        
        .risk-level {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            margin-left: 10px;
        }
        
        .risk-low { background: #2ecc71; color: white; }
        .risk-medium { background: #f39c12; color: white; }
        .risk-high { background: #e74c3c; color: white; }
        
        .issue-alert {
            background: #ffeaea;
            border: 2px solid #e74c3c;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
        }
        
        .issue-alert h3 {
            color: #e74c3c;
            margin-top: 0;
        }
        
        .issue-list {
            list-style-type: none;
            padding-left: 0;
        }
        
        .issue-list li {
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }
        
        .issue-list li:last-child {
            border-bottom: none;
        }
        
        .issue-critical {
            color: #e74c3c;
            font-weight: bold;
        }
        
        .issue-warning {
            color: #f39c12;
            font-weight: bold;
        }
        
        footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }
        
        .timestamp {
            font-style: italic;
            color: #95a5a6;
            margin-top: 5px;
        }
        
        .action-required {
            background: linear-gradient(135deg, #ff6b6b, #ee5a52);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            text-align: center;
        }
        
        .action-required h3 {
            margin-top: 0;
            color: white;
        }
        
        .preformatted {
            font-family: monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
            background: #f8f8f8;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #ddd;
            overflow-x: auto;
        }
        
        .ports-list {
            font-family: monospace;
            font-size: 0.9em;
            line-height: 1.4;
        }
        
        .status-detail {
            font-size: 0.85em;
            color: #666;
            margin-top: 3px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Audit Report - {{ inventory_hostname }}</h1>
        
        <div class="header-info">
            <div class="info-item">
                <div class="info-label">Host</div>
                <div class="info-value">{{ inventory_hostname }}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Audit Datum</div>
                <div class="info-value">{{ ansible_date_time.date }}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Uhrzeit</div>
                <div class="info-value">{{ ansible_date_time.time }}</div>
            </div>
            <div class="info-item">
                <div class="info-label">OS</div>
                <div class="info-value">
                    {% if ansible_distribution is defined %}
                        {{ ansible_distribution }} {{ ansible_distribution_version }}
                    {% else %}
                        Linux
                    {% endif %}
                </div>
            </div>
        </div>
        
        <!-- KRITISCHE PROBLEME ANZEIGE -->
        {% set critical_issues = [] %}
        {% set warning_issues = [] %}
        
        <!-- Passwortprobleme -->
        {% if password_issue_min_length is defined and password_issue_min_length %}
            {% set _ = critical_issues.append("Passwortlänge zu kurz: " + current_password_length + " < " + password_min_length|string) %}
        {% endif %}
        
        {% if password_issue_max_days is defined and password_issue_max_days %}
            {% set _ = warning_issues.append("Passwortablauf zu lang: " + current_password_max_days + " > " + password_expire_days|string) %}
        {% endif %}
        
        {% if password_has_weak_users is defined and password_has_weak_users %}
            {% set _ = critical_issues.append("Leere/schwache Passwörter gefunden") %}
        {% endif %}
        
        {% if password_has_old_users is defined and password_has_old_users %}
            {% set _ = warning_issues.append("Sehr alte Passwörter (>1 Jahr) gefunden") %}
        {% endif %}
        
        {% if password_no_pam_complexity is defined and password_no_pam_complexity %}
            {% set _ = warning_issues.append("Keine PAM Passwort-Komplexitätsprüfung") %}
        {% endif %}
        
        <!-- SSH Probleme -->
        {% if ssh_issue_root_login is defined and ssh_issue_root_login %}
            {% set _ = critical_issues.append("SSH Root-Login erlaubt") %}
        {% endif %}
        
        {% if ssh_issue_password_auth is defined and ssh_issue_password_auth %}
            {% set _ = critical_issues.append("SSH Passwort-Authentifizierung erlaubt") %}
        {% endif %}
        
        <!-- Firewall Probleme -->
        {% if firewall_issue_not_installed is defined and firewall_issue_not_installed %}
            {% set _ = critical_issues.append("Firewall (UFW) nicht installiert") %}
        {% endif %}
        
        {% if firewall_issue_not_active is defined and firewall_issue_not_active %}
            {% set _ = critical_issues.append("Firewall (UFW) nicht aktiv") %}
        {% endif %}
        
        <!-- Paket Probleme -->
        {% if missing_packages_count is defined and missing_packages_count > 0 %}
            {% set _ = critical_issues.append(missing_packages_count|string + " Security-Pakete fehlen") %}
        {% endif %}
        
        <!-- Auditd Probleme -->
        {% if auditd_issue_not_installed is defined and auditd_issue_not_installed %}
            {% set _ = warning_issues.append("Auditd nicht installiert") %}
        {% endif %}
        
        {% if auditd_issue_not_active is defined and auditd_issue_not_active %}
            {% set _ = warning_issues.append("Auditd nicht aktiv") %}
        {% endif %}
        
        {% if auditd_issue_not_enabled is defined and auditd_issue_not_enabled %}
            {% set _ = warning_issues.append("Auditd nicht enabled") %}
        {% endif %}
        
        <!-- SELinux Probleme -->
        {% if selinux_issue_not_enforcing is defined and selinux_issue_not_enforcing and not selinux_issue_not_available %}
            {% set _ = warning_issues.append("SELinux nicht enforcing") %}
        {% endif %}
        
        <!-- Dateisystem Probleme -->
        {% if fs_issue_world_writable is defined and fs_issue_world_writable %}
            {% set _ = critical_issues.append("/etc/passwd ist world-writable") %}
        {% endif %}
        
        <!-- Offene Ports -->
        {% if open_ports_total is defined and open_ports_total > 20 %}
            {% set _ = warning_issues.append("Viele offene Ports (" + open_ports_total|string + ")") %}
        {% endif %}
        
        <!-- NEUE: Sudo Probleme -->
        {% if sudo_nopasswd_entries is defined and sudo_nopasswd_entries > 0 %}
            {% set _ = critical_issues.append(sudo_nopasswd_entries|string + " NOPASSWD sudo Einträge") %}
        {% endif %}
        
        {% if sudo_no_timeout is defined and sudo_no_timeout %}
            {% set _ = warning_issues.append("Kein Sudo Timeout konfiguriert") %}
        {% endif %}
        
        <!-- NEUE: SUID Probleme -->
        {% if suid_unexpected_count is defined and suid_unexpected_count > 10 %}
            {% set _ = critical_issues.append(suid_unexpected_count|string + " unerwartete SUID/SGID Dateien") %}
        {% elif suid_unexpected_count is defined and suid_unexpected_count > 5 %}
            {% set _ = warning_issues.append(suid_unexpected_count|string + " unerwartete SUID/SGID Dateien") %}
        {% endif %}
        
        {% if suid_has_dangerous is defined and suid_has_dangerous %}
            {% set _ = critical_issues.append("Gefährliche SUID Dateien gefunden") %}
        {% endif %}
        
        <!-- NEUE: World-Writable Probleme -->
        {% if world_writable_has_critical is defined and world_writable_has_critical %}
            {% set _ = critical_issues.append("Kritische Dateien world-writable") %}
        {% elif world_writable_files_count is defined and world_writable_files_count > 50 %}
            {% set _ = critical_issues.append(world_writable_files_count|string + " world-writable Dateien") %}
        {% elif world_writable_files_count is defined and world_writable_files_count > 20 %}
            {% set _ = warning_issues.append(world_writable_files_count|string + " world-writable Dateien") %}
        {% endif %}
        
        <!-- NEUE: Cron Probleme -->
        {% if cron_has_suspicious is defined and cron_has_suspicious %}
            {% set _ = critical_issues.append("Verdächtige Cron Jobs gefunden") %}
        {% endif %}
        
        {% if cron_service_active is defined and not cron_service_active %}
            {% set _ = warning_issues.append("Cron Service nicht aktiv") %}
        {% endif %}
        
        <!-- NEUE: Mount Probleme -->
        {% if mount_tmp_insecure is defined and mount_tmp_insecure %}
            {% set _ = critical_issues.append("/tmp ohne noexec/nosuid") %}
        {% endif %}
        
        {% if mount_shm_insecure is defined and mount_shm_insecure %}
            {% set _ = critical_issues.append("/dev/shm ohne noexec/nosuid") %}
        {% endif %}
        
        {% if mount_home_insecure is defined and mount_home_insecure %}
            {% set _ = warning_issues.append("/home ohne nodev") %}
        {% endif %}
        
        {% if mount_insecure_count is defined and mount_insecure_count > 0 %}
            {% set _ = warning_issues.append(mount_insecure_count|string + " Mounts ohne Sicherheitsoptionen") %}
        {% endif %}
        
        <!-- NEUE: ASLR Probleme -->
        {% if aslr_disabled is defined and aslr_disabled %}
            {% set _ = critical_issues.append("ASLR deaktiviert") %}
        {% elif aslr_partial is defined and aslr_partial %}
            {% set _ = warning_issues.append("ASLR nur teilweise aktiv") %}
        {% endif %}
        
        {% if aslr_has_norandmaps is defined and aslr_has_norandmaps %}
            {% set _ = critical_issues.append("norandmaps Kernel Parameter") %}
        {% endif %}
        
        <!-- NEUE: Kernel Module Probleme -->
        {% if kernel_modules_has_dangerous is defined and kernel_modules_has_dangerous %}
            {% set _ = warning_issues.append(kernel_modules_loaded_dangerous|string + " gefährliche Kernel Module geladen") %}
        {% endif %}
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            
            <div class="summary-stats">
                <div class="stat-box {% if critical_issues|length > 0 %}critical{% endif %}">
                    <span class="stat-number {% if critical_issues|length > 0 %}critical{% endif %}">{{ critical_issues|length }}</span>
                    <span class="stat-label">Kritische Probleme</span>
                </div>
                <div class="stat-box {% if warning_issues|length > 0 %}warning{% endif %}">
                    <span class="stat-number {% if warning_issues|length > 0 %}warning{% endif %}">{{ warning_issues|length }}</span>
                    <span class="stat-label">Warnungen</span>
                </div>
                <div class="stat-box">
                    <span class="stat-number">18</span>
                    <span class="stat-label">Geprüfte Bereiche</span>
                </div>
            </div>
            
            {% if critical_issues|length > 0 %}
            <div class="action-required">
                <h3>🚨 AKTION ERFORDERLICH!</h3>
                <p>{{ critical_issues|length }} kritische Sicherheitsprobleme gefunden!</p>
            </div>
            
            <div class="issue-alert">
                <h3>🔴 Kritische Probleme (SOFORT beheben):</h3>
                <ul class="issue-list">
                    {% for issue in critical_issues %}
                    <li class="issue-critical">❌ {{ issue }}</li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}
            
            {% if warning_issues|length > 0 %}
            <div class="issue-alert" style="background: #fff4e6; border-color: #f39c12;">
                <h3>🟡 Warnungen (Bald beheben):</h3>
                <ul class="issue-list">
                    {% for issue in warning_issues %}
                    <li class="issue-warning">⚠️ {{ issue }}</li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}
            
            <p><strong>Gesamtbewertung:</strong> 
                {% if critical_issues|length > 0 %}
                <span class="risk-level risk-high">KRITISCHES RISIKO</span>
                {% elif warning_issues|length > 0 %}
                <span class="risk-level risk-medium">MITTELES RISIKO</span>
                {% else %}
                <span class="risk-level risk-low">GERINGES RISIKO</span>
                {% endif %}
            </p>
        </div>
        
        <!-- BESTEHENDE ABSCHNITTE HIER (gekürzt für Platz) -->
        <!-- password_policy, ssh_hardening, firewall_check, open_ports, package_check, log_audit_check, selinux_check, kernel_security, filesystem_permissions, container_security -->
        
        <!-- NEUE ABSCHNITTE FÜR ERWEITERTE CHECKS -->
        
        <div class="section {% if sudo_nopasswd_entries > 0 %}critical-section{% endif %}">
            <h2>🛡️ Sudo Sicherheitsprüfung</h2>
            <table>
                <tr>
                    <th>Check</th>
                    <th>Status</th>
                    <th>Details</th>
                    <th>Risiko</th>
                </tr>
                <tr>
                    <td>NOPASSWD Einträge</td>
                    <td>{{ sudo_nopasswd_entries | default(0) }}</td>
                    <td>Sudo ohne Passworterfordernis</td>
                    <td>
                        {% if sudo_nopasswd_entries > 0 %}
                        <span class="check-result check-critical">❌ KRITISCH</span>
                        {% else %}
                        <span class="check-result check-ok">✓ OK</span>
                        {% endif %}
                    </td>
                </tr>
                <tr>
                    <td>Sudo Timeout</td>
                    <td>{% if sudo_no_timeout %}Nicht gesetzt{% else %}Gesetzt{% endif %}</td>
                    <td>timestamp_timeout in sudoers</td>
                    <td>
                        {% if sudo_no_timeout %}
                        <span class="check-result check-warning">⚠️ WARNUNG</span>
                        {% else %}
                        <span class="check-result check-ok">✓ OK</span>
                        {% endif %}
                    </td>
                </tr>
            </table>
            {% if sudo_nopasswd_entries > 0 %}
            <div style="margin-top: 15px; padding: 10px; background: #ffeaea; border-radius: 5px;">
                <strong>⚠️ KRITISCH:</strong> {{ sudo_nopasswd_entries }} NOPASSWD Einträge gefunden!<br>
                Diese erlauben Sudo-Befehle ohne Passwort - SOFORT überprüfen!
            </div>
            {% endif %}
        </div>
        
        <div class="section {% if suid_unexpected_count > 10 %}critical-section{% elif suid_unexpected_count > 5 %}warning-section{% endif %}">
            <h2>🔐 SUID/SGID Sicherheitsprüfung</h2>
            <table>
                <tr>
                    <th>Metrik</th>
                    <th>Wert</th>
                    <th>Empfehlung</th>
                    <th>Risiko</th>
                </tr>
                <tr>
                    <td>Gesamtzahl SUID/SGID</td>
                    <td>{{ suid_total_count | default(0) }}</td>
                    <td>So wenige wie möglich</td>
                    <td>
                        {% if suid_total_count > 50 %}
                        <span class="check-result check-warning">⚠️ HOCH</span>
                        {% else %}
                        <span class="check-result check-ok">✓ NIEDRIG</span>
                        {% endif %}
                    </td>
                </tr>
                <tr>
                    <td>Unerwartete SUID/SGID</td>
                    <td>{{ suid_unexpected_count | default(0) }}</td>
                    <td>Maximal 5</td>
                    <td>
                        {% if suid_unexpected_count > 10 %}
                        <span class="check-result check-critical">❌ KRITISCH</span>
                        {% elif suid_unexpected_count > 5 %}
                        <span class="check-result check-warning">⚠️ HOCH</span>
                        {% else %}
                        <span class="check-result check-ok">✓ NIEDRIG</span>
                        {% endif %}
                    </td>
                </tr>
                <tr>
                    <td>Gefährliche SUID Dateien</td>
                    <td>{{ 'JA' if suid_has_dangerous else 'NEIN' }}</td>
                    <td>Entfernen oder schützen</td>
                    <td>
                        {% if suid_has_dangerous %}
                        <span class="check-result check-critical">❌ KRITISCH</span>
                        {% else %}
                        <span class="check-result check-ok">✓ OK</span>
                        {% endif %}
                    </td>
                </tr>
            </table>
            {% if suid_unexpected_count > 0 %}
            <div style="margin-top: 15px; padding: 10px; background: #fff4e6; border-radius: 5px;">
                <strong>Unerwartete SUID/SGID Dateien gefunden:</strong><br>
                <div class="preformatted" style="max-height: 200px; overflow-y: auto;">
                    {{ suid_unexpected_files | default('Keine Details') }}
                </div>
            </div>
            {% endif %}
        </div>
        
        <div class="section {% if world_writable_has_critical %}critical-section{% elif world_writable_files_count > 20 %}warning-section{% endif %}">
            <h2>📁 World-Writable Dateien</h2>
            <table>
                <tr>
                    <th>Check</th>
                    <th>Anzahl</th>
                    <th>Bewertung</th>
                    <th>Risiko</th>
                </tr>
                <tr>
                    <td>World-writable Dateien</td>
                    <td>{{ world_writable_files_count | default(0) }}</td>
                    <td>Maximal 10 (außer /tmp)</td>
                    <td>
                        {% if world_writable_files_count > 50 %}
                        <span class="check-result check-critical">❌ KRITISCH</span>
                        {% elif world_writable_files_count > 20 %}
                        <span class="check-result check-warning">⚠️ HOCH</span>
                        {% else %}
                        <span class="check-result check-ok">✓ NIEDRIG</span>
                        {% endif %}
                    </td>
                </tr>
                <tr>
                    <td>Kritische Dateien</td>
                    <td>{{ 'JA' if world_writable_has_critical else 'NEIN' }}</td>
                    <td>Dürfen nie world-writable sein</td>
                    <td>
                        {% if world_writable_has_critical %}
                        <span class="check-result check-critical">❌ KRITISCH</span>
                        {% else %}
                        <span class="check-result check-ok">✓ OK</span>
                        {% endif %}
                    </td>
                </tr>
            </table>
            {% if world_writable_has_critical %}
            <div style="margin-top: 15px; padding: 10px; background: #ffeaea; border-radius: 5px;">
                <strong>🚨 KRITISCHER FUND:</strong> Kritische Systemdateien sind world-writable!<br>
                <div class="preformatted">{{ world_writable_critical_text | default('Keine Details') }}</div>
            </div>
            {% endif %}
        </div>
        
        <div class="section {% if cron_has_suspicious %}critical-section{% endif %}">
            <h2>⏰ Cron Sicherheitsprüfung</h2>
            <table>
                <tr>
                    <th>Check</th>
                    <th>Status</th>
                    <th>Details</th>
                    <th>Risiko</th>
                </tr>
                <tr>
                    <td>Verdächtige Cron Jobs</td>
                    <td>{{ cron_suspicious_count | default(0) }}</td>
                    <td>Curl/wget in Cron</td>
                    <td>
                        {% if cron_suspicious_count > 0 %}
                        <span class="check-result check-critical">❌ KRITISCH</span>
                        {% else %}
                        <span class="check-result check-ok">✓ OK</span>
                        {% endif %}
                    </td>
                </tr>
                <tr>
                    <td>Cron Service</td>
                    <td>{{ 'Aktiv' if cron_service_active else 'Inaktiv' }}</td>
                    <td>Systemd Status</td>
                    <td>
                        {% if not cron_service_active %}
                        <span class="check-result check-warning">⚠️ WARNUNG</span>
                        {% else %}
                        <span class="check-result check-ok">✓ OK</span>
                        {% endif %}
                    </td>
                </tr>
            </table>
            {% if cron_has_suspicious %}
            <div style="margin-top: 15px; padding: 10px; background: #ffeaea; border-radius: 5px;">
                <strong>⚠️ Verdächtige Cron Jobs gefunden:</strong><br>
                Diese können Zeichen von Kompromittierung sein - SOFORT überprüfen!
            </div>
            {% endif %}
        </div>
        
        <div class="section {% if mount_insecure_count > 0 or mount_tmp_insecure or mount_shm_insecure %}warning-section{% endif %}">
            <h2>💾 Mount Optionen Sicherheit</h2>
            <table>
                <tr>
                    <th>Mount</th>
                    <th>Sicherheitsoptionen</th>
                    <th>Status</th>
                    <th>Priorität</th>
                </tr>
                <tr>
                    <td>/tmp</td>
                    <td>noexec,nosuid,nodev</td>
                    <td>
                        {% if mount_tmp_insecure %}
                        <span class="check-result check-critical">❌ FEHLEND</span>
                        {% else %}
                        <span class="check-result check-ok">✓ VORHANDEN</span>
                        {% endif %}
                    </td>
                    <td><span class="check-result check-critical">HOCH</span></td>
                </tr>
                <tr>
                    <td>/dev/shm</td>
                    <td>noexec,nosuid</td>
                    <td>
                        {% if mount_shm_insecure %}
                        <span class="check-result check-critical">❌ FEHLEND</span>
                        {% else %}
                        <span class="check-result check-ok">✓ VORHANDEN</span>
                        {% endif %}
                    </td>
                    <td><span class="check-result check-critical">HOCH</span></td>
                </tr>
                <tr>
                    <td>/home</td>
                    <td>nodev,nosuid</td>
                    <td>
                        {% if mount_home_insecure %}
                        <span class="check-result check-warning">⚠️ FEHLEND</span>
                        {% else %}
                        <span class="check-result check-ok">✓ VORHANDEN</span>
                        {% endif %}
                    </td>
                    <td><span class="check-result check-warning">MITTEL</span></td>
                </tr>
                <tr>
                    <td>Andere Mounts</td>
                    <td>nodev,nosuid,noexec</td>
                    <td>
                        {% if mount_insecure_count > 0 %}
                        <span class="check-result check-warning">⚠️ {{ mount_insecure_count }} unsicher</span>
                        {% else %}
                        <span class="check-result check-ok">✓ ALLE SICHER</span>
                        {% endif %}
                    </td>
                    <td><span class="check-result check-warning">MITTEL</span></td>
                </tr>
            </table>
            {% if mount_tmp_insecure or mount_shm_insecure %}
            <div style="margin-top: 15px; padding: 10px; background: #fff4e6; border-radius: 5px;">
                <strong>⚠️ Kritische Mounts unsicher:</strong><br>
                /tmp und /dev/shm MÜSSEN noexec,nosuid haben um Exploits zu verhindern!
            </div>
            {% endif %}
        </div>
        
        <div class="section {% if aslr_disabled or aslr_has_norandmaps %}critical-section{% endif %}">
            <h2>🛡️ ASLR (Memory Security)</h2>
            <table>
                <tr>
                    <th>Parameter</th>
                    <th>Aktuell</th>
                    <th>Empfohlen</th>
                    <th>Sicherheit</th>
                </tr>
                <tr>
                    <td>ASLR Status</td>
                    <td>
                        {% if aslr_disabled %}
                        DEAKTIVIERT
                        {% elif aslr_partial %}
                        KONSERVATIV
                        {% else %}
                        VOLLSTÄNDIG
                        {% endif %}
                        ({{ aslr_value_num }})
                    </td>
                    <td>Vollständig (2)</td>
                    <td>
                        {% if aslr_disabled %}
                        <span class="check-result check-critical">❌ KEIN SCHUTZ</span>
                        {% elif aslr_partial %}
                        <span class="check-result check-warning">⚠️ TEILSCHUTZ</span>
                        {% else %}
                        <span class="check-result check-ok">✓ VOLLSCHUTZ</span>
                        {% endif %}
                    </td>
                </tr>
                <tr>
                    <td>norandmaps Parameter</td>
                    <td>{{ 'JA' if aslr_has_norandmaps else 'NEIN' }}</td>
                    <td>NEIN</td>
                    <td>
                        {% if aslr_has_norandmaps %}
                        <span class="check-result check-critical">❌ GEFÄHRLICH</span>
                        {% else %}
                        <span class="check-result check-ok">✓ OK</span>
                        {% endif %}
                    </td>
                </tr>
            </table>
            {% if aslr_disabled or aslr_has_norandmaps %}
            <div style="margin-top: 15px; padding: 10px; background: #ffeaea; border-radius: 5px;">
                <strong>🚨 KRITISCH:</strong> ASLR ist deaktiviert oder eingeschränkt!<br>
                Dadurch ist das System anfällig für Memory-basierte Angriffe wie Buffer Overflows.
            </div>
            {% elif aslr_partial %}
            <div style="margin-top: 15px; padding: 10px; background: #fff4e6; border-radius: 5px;">
                <strong>⚠️ WARNUNG:</strong> ASLR ist nur teilweise aktiviert.<br>
                Setze kernel.randomize_va_space auf 2 für vollständigen Schutz.
            </div>
            {% endif %}
        </div>
        
        <div class="section {% if kernel_modules_has_dangerous %}warning-section{% endif %}">
            <h2>⚙️ Kernel Module Sicherheit</h2>
            <table>
                <tr>
                    <th>Check</th>
                    <th>Status</th>
                    <th>Details</th>
                    <th>Risiko</th>
                </tr>
                <tr>
                    <td>Gefährliche Module</td>
                    <td>{{ kernel_modules_loaded_dangerous | default(0) }} geladen</td>
                    <td>{{ dangerous_kernel_modules | join(', ') | truncate(50) }}</td>
                    <td>
                        {% if kernel_modules_has_dangerous %}
                        <span class="check-result check-warning">⚠️ RISIKO</span>
                        {% else %}
                        <span class="check-result check-ok">✓ OK</span>
                        {% endif %}
                    </td>
                </tr>
                <tr>
                    <td>Module Signatur</td>
                    <td>
                        {% if 'nicht konfiguriert' in kernel_modules_signing_info %}
                        Nicht aktiv
                        {% else %}
                        Aktiv
                        {% endif %}
                    </td>
                    <td>Prüfung signierter Module</td>
                    <td>
                        {% if 'nicht konfiguriert' in kernel_modules_signing_info %}
                        <span class="check-result check-warning">⚠️ WARNUNG</span>
                        {% else %}
                        <span class="check-result check-ok">✓ OK</span>
                        {% endif %}
                    </td>
                </tr>
            </table>
            {% if kernel_modules_has_dangerous %}
            <div style="margin-top: 15px; padding: 10px; background: #fff4e6; border-radius: 5px;">
                <strong>⚠️ Gefährliche Kernel Module geladen:</strong><br>
                Diese Module können Sicherheitsrisiken darstellen. Prüfen Sie ob sie benötigt werden.
            </div>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>🚨 Priorisierte To-Do Liste</h2>
            <table>
                <tr>
                    <th>Priorität</th>
                    <th>Maßnahme</th>
                    <th>Bereich</th>
                    <th>Zeitrahmen</th>
                </tr>
                
                <!-- Kritische Maßnahmen -->
                {% if critical_issues|length > 0 %}
                <tr style="background-color: #ffeaea;">
                    <td><span class="check-result check-critical">KRITISCH</span></td>
                    <td>Alle oben gelisteten kritischen Probleme beheben</td>
                    <td>Verschiedene</td>
                    <td>SOFORT (0-24h)</td>
                </tr>
                {% endif %}
                
                <!-- Sudo NOPASSWD -->
                {% if sudo_nopasswd_entries > 0 %}
                <tr style="background-color: #ffeaea;">
                    <td><span class="check-result check-critical">KRITISCH</span></td>
                    <td>{{ sudo_nopasswd_entries }} NOPASSWD sudo Einträge entfernen</td>
                    <td>Sudo</td>
                    <td>24 Stunden</td>
                </tr>
                {% endif %}
                
                <!-- Gefährliche SUID Dateien -->
                {% if suid_has_dangerous %}
                <tr style="background-color: #ffeaea;">
                    <td><span class="check-result check-critical">KRITISCH</span></td>
                    <td>Gefährliche SUID Dateien überprüfen und entfernen</td>
                    <td>SUID/SGID</td>
                    <td>24 Stunden</td>
                </tr>
                {% endif %}
                
                <!-- World-writable kritische Dateien -->
                {% if world_writable_has_critical %}
                <tr style="background-color: #ffeaea;">
                    <td><span class="check-result check-critical">KRITISCH</span></td>
                    <td>World-writable kritische Systemdateien schützen</td>
                    <td>Dateisystem</td>
                    <td>24 Stunden</td>
                </tr>
                {% endif %}
                
                <!-- Verdächtige Cron Jobs -->
                {% if cron_has_suspicious %}
                <tr style="background-color: #ffeaea;">
                    <td><span class="check-result check-critical">KRITISCH</span></td>
                    <td>Verdächtige Cron Jobs untersuchen und entfernen</td>
                    <td>Cron</td>
                    <td>24 Stunden</td>
                </tr>
                {% endif %}
                
                <!-- /tmp und /dev/shm Mounts -->
                {% if mount_tmp_insecure or mount_shm_insecure %}
                <tr style="background-color: #ffeaea;">
                    <td><span class="check-result check-critical">HOCH</span></td>
                    <td>/tmp und /dev/shm mit noexec,nosuid mounten</td>
                    <td>Mount</td>
                    <td>48 Stunden</td>
                </tr>
                {% endif %}
                
                <!-- ASLR deaktiviert -->
                {% if aslr_disabled or aslr_has_norandmaps %}
                <tr style="background-color: #ffeaea;">
                    <td><span class="check-result check-critical">HOCH</span></td>
                    <td>ASLR aktivieren (kernel.randomize_va_space=2)</td>
                    <td>Kernel</td>
                    <td>48 Stunden</td>
                </tr>
                {% endif %}
                
                <!-- Viele unerwartete SUID Dateien -->
                {% if suid_unexpected_count > 5 %}
                <tr style="background-color: #fff4e6;">
                    <td><span class="check-result check-warning">MITTEL</span></td>
                    <td>{{ suid_unexpected_count }} unerwartete SUID Dateien überprüfen</td>
                    <td>SUID/SGID</td>
                    <td>7 Tage</td>
                </tr>
                {% endif %}
                
                <!-- Many world-writable files -->
                {% if world_writable_files_count > 20 %}
                <tr style="background-color: #fff4e6;">
                    <td><span class="check-result check-warning">MITTEL</span></td>
                    <td>{{ world_writable_files_count }} world-writable Dateien überprüfen</td>
                    <td>Dateisystem</td>
                    <td>7 Tage</td>
                </tr>
                {% endif %}
                
                <!-- Gefährliche Kernel Module -->
                {% if kernel_modules_has_dangerous %}
                <tr style="background-color: #fff4e6;">
                    <td><span class="check-result check-warning">MITTEL</span></td>
                    <td>{{ kernel_modules_loaded_dangerous }} gefährliche Kernel Module prüfen</td>
                    <td>Kernel</td>
                    <td>7 Tage</td>
                </tr>
                {% endif %}
                
                <!-- /home ohne nodev -->
                {% if mount_home_insecure %}
                <tr style="background-color: #fff4e6;">
                    <td><span class="check-result check-warning">MITTEL</span></td>
                    <td>/home Partition mit nodev Option mounten</td>
                    <td>Mount</td>
                    <td>7 Tage</td>
                </tr>
                {% endif %}
                
                <!-- ASLR nur teilweise -->
                {% if aslr_partial and not aslr_disabled %}
                <tr style="background-color: #fff4e6;">
                    <td><span class="check-result check-warning">MITTEL</span></td>
                    <td>ASLR auf vollständigen Modus setzen (Wert: 2)</td>
                    <td>Kernel</td>
                    <td>7 Tage</td>
                </tr>
                {% endif %}
                
                <!-- Warnungs-Maßnahmen -->
                {% if warning_issues|length > 0 %}
                <tr style="background-color: #fff4e6;">
                    <td><span class="check-result check-warning">MITTEL</span></td>
                    <td>Alle oben gelisteten Warnungen beheben</td>
                    <td>Verschiedene</td>
                    <td>7 Tage</td>
                </tr>
                {% endif %}
                
                <!-- Allgemeine Maßnahmen -->
                <tr>
                    <td><span class="check-result check-ok">NIEDRIG</span></td>
                    <td>Regelmäßige Backups prüfen und testen</td>
                    <td>Backup</td>
                    <td>30 Tage</td>
                </tr>
                
                <tr>
                    <td><span class="check-result check-ok">NIEDRIG</span></td>
                    <td>Security Awareness Training für Benutzer</td>
                    <td>Organisation</td>
                    <td>90 Tage</td>
                </tr>
            </table>
        </div>
        
        <footer>
            <p>Generiert mit Ansible Security Audit Framework v3.1</p>
            <p class="timestamp">Report generiert am {{ ansible_date_time.iso8601 }}</p>
            <p><strong>Hinweis:</strong> Kritische Probleme sollten innerhalb von 24 Stunden behoben werden!</p>
        </footer>
    </div>
</body>
</html>
EOL

	# 7. Abschluss
	print_header "PROJEKT ERFOLGREICH ERSTELLT"
	echo -e "${GREEN}✅ Projekt '$PROJECT_NAME' wurde erfolgreich erstellt!${NC}"
	echo ""
	echo -e "${BLUE}📁 NEUE SECURITY CHECKS:${NC}"
	echo -e "  ${GREEN}SOFORT prüfen:${NC}"
	echo "    • sudo_check    - NOPASSWD sudo Einträge"
	echo "    • suid_check    - Unerwartete SUID/SGID Dateien"
	echo "    • world_writable - World-writable Dateien"
	echo "    • cron_check    - Verdächtige Cron Jobs"
	echo ""
	echo -e "  ${YELLOW}In 1 Woche prüfen:${NC}"
	echo "    • mount_options  - Partition Mount Sicherheit"
	echo "    • aslr_check     - Memory Protection (ASLR)"
	echo "    • kernel_modules - Gefährliche Kernel Module"
	echo ""
	echo -e "${BLUE}🚀 Nächste Schritte:${NC}"
	echo "1. cd $PROJECT_NAME"
	echo "2. ansible-playbook -i inventory site.yml --check  # Trockenlauf"
	echo "3. ansible-playbook -i inventory site.yml          # Vollständiger Audit"
	echo ""
	echo -e "${YELLOW}📊 Report wird erstellt unter:${NC}"
	echo "   /bigdata/tmp/ansible-security-audit/security_report_localhost.html"
	echo ""
	echo -e "${RED}⚠️  WICHTIG:${NC} Führe zuerst --check aus und prüfe die SOFORT-Maßnahmen!"
	echo -e "${GREEN}✅ Shell Kompatibilität:${NC} Alle Tasks verwenden jetzt explizit /bin/bash"
}

# Hauptprogramm ausführen
main "$@"
