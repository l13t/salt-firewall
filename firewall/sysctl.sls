{% set keep_enabled = salt['pillar.get']('keepalived:enabled', False) %}
/etc/sysctl.d/10-forward.conf:
  file.managed:
    - source: salt://firewall/files/10-forward.conf
    - user: root
    - group: root
    - mode: 600

{%- if keep_enabled %}
net.ipv4.conf.default.rp_filter:
  sysctl.present:
    - value: 0

net.ipv4.conf.all.rp_filter:
  sysctl.present:
    - value: 0

net.ipv4.conf.eth0.rp_filter:
  sysctl.present:
    - value: 0

net.ipv4.conf.eth1.rp_filter:
  sysctl.present:
    - value: 0

/etc/sysctl.d/30-firewall.conf:
  file.managed:
    - source: salt://firewall/files/30-firewall.conf
    - user: root
    - group: root
    - mode: 600

/etc/sysctl.d/60-keepalived.conf:
  file.managed:
    - source: salt://firewall/files/60-keepalived.conf
    - user: root
    - group: root
    - mode: 600
{%- endif %}

