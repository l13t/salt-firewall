{%- if salt['pillar.get']('huge_fw:enabled') %}

  {% set firewall = salt['pillar.get']('huge_fw', {}) %}
  {%- for ips, ips_details in firewall.get('ipset', {}).items() %}

{{ ips }}:
  ipset.set_present:
    - set_type: hash:net
    - family: ipv4
    - comment: True

    {%- set comm = ips_details.get('comment', '') %}

{{ ips }}_entries:
  ipset.present:
    - set_name: {{ ips }}
    - entry:
    {%- for ips_ip in ips_details.get('ips_allow') %}
      - {{ ips_ip }}
    {%- endfor %}
    {%- if comm != '' %}
    - comment: {{ comm }}
    {%- endif %}
    - require:
      - ipset: {{ ips }}

  {%- endfor %}

{%- endif %}
