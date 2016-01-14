{% set keep_enabled = salt['pillar.get']('keepalived:enabled', False) %}
{% set keep_install = salt['pillar.get']('keepalived:install', False) %}
{% set conn_enabled = salt['pillar.get']('conntrackd:enabled', False) %}
{% set conn_install = salt['pillar.get']('conntrackd:install', False) %}
{% set lb_enabled = salt['pillar.get']('ldirector:enabled', False) %}
{% set lb_install = salt['pillar.get']('ldirector:install', False) %}

{% if keep_enabled %}
  {% if keep_install %}
keepalived:
  pkg.installed
  {% endif %}

/etc/keepalived/keepalived.conf:
  file.managed:
    - source: salt://firewall/files/keepalived.conf
    - template: jinja
    - user: root
    - group: root
    - mode: 600

/etc/keepalived/bypass_ipvs.sh:
  file.managed:
    - source: salt://firewall/files/bypass_ipvs.sh
    - user: root
    - group: root
    - mode: 755

keepalived_restart:
  service.running:
    - watch:
      - file: /etc/keepalived/keepalived.conf
    - name: keepalived
{% endif %}

{% if conn_enabled %}
  {% if conn_install %}
conntrackd:
  pkg.installed
  {% endif %}

/etc/conntrackd/conntrackd.conf:
  file.managed:
    - source: salt://firewall/files/conntrackd.conf
    - template: jinja
    - user: root
    - group: root
    - mode: 600

/etc/conntrackd/primary-backup.sh:
  file.managed:
    - source: salt://firewall/files/primary-backup.sh
    - user: root
    - group: root
    - mode: 755

conntrackd_restart:
  service.running:
    - watch:
      - file: /etc/conntrackd/conntrackd.conf
    - name: conntrackd
{% endif %}

{%- if conn_enabled or keep_enabled %}
/root/bin:
  file.directory:
    - user: root
    - group: root
    - mode: 755
    - makedirs: True

/root/bin/ms_cluster.sh:
  file.managed:
    - source: salt://firewall/files/ms_cluster.sh
    - template: jinja
    - user: root
    - group: root
    - mode: 755
{%- endif %}

{%- if lb_enabled %}
  {%- if lb_install %}
ldirectord:
  pkg.installed
  {%- endif %}

/etc/ldirectord.cf:
  file.managed:
    - source: salt://firewall/files/ldirector.cf
    - template: jinja
    - user: root
    - group: root
    - mode: 644
{%- endif %}

/usr/lib/python2.7/dist-packages/salt/modules/iptables.py:
  file.patch:
    - source: salt://firewall/files/salt_modules_iptables_py.patch
    - hash: md5=617165531e65a8864dca61744ea45087
    - options: -f

