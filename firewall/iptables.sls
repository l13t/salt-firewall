{%- if salt['pillar.get']('huge_fw:enabled') %}
  {% set firewall = salt['pillar.get']('huge_fw', {}) %}
  {% set install = firewall.get('install', False) %}
  {% set packages = salt['grains.filter_by']({
                    'Debian': ['iptables', 'iptables-persistent', 'ipset'],
                    'RedHat': ['iptables', 'ipset'],
                    'default': 'Debian'}) %}

  {%- if install %}
# Install required packages for firewalling      
iptables_packages:
  pkg.installed:
    - pkgs:
    {%- for pkg in packages %}
      - {{pkg}}
    {%- endfor %}

/etc/init.d/iptables-persistent:
  file.managed:
    - source: salt://firewall/files/iptables-persistent
    - user: root
    - group: root
    - mode: 755

iptables-persistent:
  service.running:
    - enable: True
    - reload: True

  {%- endif %}

# Apply chains
  {%- for root_chain, rc_details in firewall.get('root_chains', {}).items() %}
    {%- for j in range(0,100) %}
      {%- set uc_details = rc_details.get(j, {}) %}
{%- if uc_details and uc_details|count != 0 %}
      {%- set in_dev = uc_details.get('src_dev', '') %}
      {%- set out_dev = uc_details.get('dst_dev', '') %}
      {%- set chain_name = uc_details.get('ch_name', '') %}
      {%- set table = salt['pillar.get']('huge_fw:chains:%s:table' % chain_name, 'filter') %}
      {%- if chain_name != '' %}

iptables_{{ chain_name }}_HOOK_removal:
  iptables.delete:
    - table: {{ table }}
    - chain: {{ chain_name }}_HOOK
        {%- if in_dev != '' %}
    - i: {{ in_dev }}
        {%- endif %}
        {%- if out_dev != '' %}
    - o: {{ out_dev }}
        {%- endif %}
    - jump: {{ chain_name }}

iptables_{{ root_chain }}_removal_{{ chain_name }}_HOOK:
  iptables.delete:
    - table: {{ table }}
    - chain: {{ root_chain }}
    - jump: {{ chain_name }}_HOOK

{{ chain_name }}_remove_initial:
  iptables.chain_absent:
    - table: {{ table }}
    - name: {{ chain_name }}

{{ chain_name }}_HOOK_remove:
  iptables.chain_absent:
    - table: {{ table }}
    - name: {{ chain_name }}_HOOK

{{ chain_name }}:
  iptables.chain_present:
    - table: {{ table }}

{{ chain_name }}_HOOK:
  iptables.chain_present:
    - table: {{ table }}

iptables_{{ chain_name }}_HOOK:
  iptables.append:
    - table: {{ table }}
    - chain: {{ chain_name }}_HOOK
        {%- if in_dev != '' %}
    - i: {{ in_dev }}
        {%- endif %}
        {%- if out_dev != '' %}
    - o: {{ out_dev }}
        {%- endif %}
    - jump: {{ chain_name }}
      {%- endif %}

iptables_{{ root_chain }}_{{ chain_name }}_HOOK:
  iptables.append:
    - table: {{ table }}
    - chain: {{ root_chain }}
    - jump: {{ chain_name }}_HOOK
{%- endif %}
    {%- endfor %}
  {%- endfor %}

# Generate chains for firewall
  {%- for chain, chain_details in firewall.get('chains', {}).items() %}
    {%- set chain_def = chain_details.get('defaults', False) %}
    {%- set table = chain_details.get('table', 'filter') %}
    {%- if chain_def %}

iptables_{{ chain }}_rule1:
  iptables.append:
    - table: {{ table }}
    - match:
      - comment
      - state
    - comment: {{ chain }}_rule1 Initial Rule
    - chain: {{ chain }}
    - connstate: RELATED,ESTABLISHED
    - jump: RETURN
    {%- endif %}

    {%- for i in range(2, 9999) %}
      {%- set rule_details = chain_details.get(i, {}) %}
      {#- if rule_details and rule_details.comment  #}
      {%- if rule_details and rule_details|count != 0 %}
        {%- set jump = rule_details.get('jump', 'ACCEPT') %}
        {%- set proto = rule_details.get('proto', 'tcp') %}
        {%- set s_port = rule_details.get('s_port', '') %}
        {%- set s_ports = rule_details.get('sports', []) %}
        {%- if s_ports == None %}
          {%- set sports = '' %}
        {%- else %}
          {%- set sports = s_ports|join(',') %}
        {%- endif %}
        {%- set d_port = rule_details.get('d_port', '') %}
        {%- set d_ports = rule_details.get('dports', []) %}
        {%- if d_ports == None %}
          {%- set dports = '' %}
        {%- else %}
          {%- set dports = d_ports|join(',') %}
        {%- endif %}
        {%- set src_list = rule_details.get('ips_in', '') %}
        {%- set dst_list = rule_details.get('ips_out', '') %}
        {%- set comment = rule_details.get('comment', '') %}
        {%- set in_dev = rule_details.get('dev_in', '') %}
        {%- set out_dev = rule_details.get('dev_out', '') %}
        {%- set has_set = False %}
        {%- set dst_range = rule_details.get('dst-range', '') %}
        {%- set to_destination = rule_details.get('to-destination', '') %}

iptables_{{ chain }}_rule{{ i }}:
  iptables.append:
          {%- if salt['jinja_re.re_match']('[a-zA-Z]', src_list) %}
            {%- set has_set = True %}
          {%- endif %}
          {%- if salt['jinja_re.re_match']('[a-zA-Z]', dst_list) %}
            {%- set has_set = True %}
          {%- endif %}
          {%- set m_ipsec = rule_details.get('match-ipsec', 'False') %}
    - table: {{ table }}
    - match:
      - comment
          {%- if m_ipsec == True %}
      - policy
          {%- endif %}
          {%- if dst_range != '' %}
      - iprange
          {%- endif %}
    - chain: {{ chain }}
          {%- if in_dev != '' %}
    - i: {{ in_dev }}
          {%- endif %}
          {%- if out_dev != '' %}
    - o: {{ out_dev }}
          {%- endif %}
    - jump: {{ jump }}
        {%- if m_ipsec == True %}
    - dir: in
    - pol: ipsec
        {%- else %}
          {%- if to_destination != ''%}
    - to-destination: {{ to_destination }}
          {%- endif %}
          {%- if dst_range != ''%}
    - dst-range: {{ dst_range }}
          {%- endif %}
    - proto: {{ proto }}
          {%- if dports != '' %}
    - dports: {{ dports }}
          {%- else %}
            {%- if d_port != '' %}
    - dport: {{ d_port }}
            {%- endif %}
          {%- endif %}
          {%- if sports != '' %}
    - sports: {{ sports }}
          {%- else %}
            {%- if s_port != '' %}
    - sport: {{ s_port }}
            {%- endif %}
          {%- endif %}

          {%- if has_set %}
    - match-set:
            {%- if salt['jinja_re.re_match']('[a-zA-Z]', dst_list) %}
      - {{ dst_list }} dst
            {%- endif %}
            {%- if salt['jinja_re.re_match']('[a-zA-Z]', src_list) %}
      - {{ src_list }} src
            {%- endif %}
          {%- endif %}
          {%- if src_list != '' %}
            {%- if not salt['jinja_re.re_match']('[a-zA-Z]', src_list) %}
              {%- if dst_list != "0.0.0.0/0" %}
    - s: {{ src_list }}
              {%- endif %}
            {%- endif %}
          {%- endif %}
          {%- if dst_list != '' %}
            {%- if not salt['jinja_re.re_match']('[a-zA-Z]', dst_list) %}
              {%- if dst_list != "0.0.0.0/0" %}
    - d: {{ dst_list }}
              {%- endif %}
            {%- endif %}
          {%- endif %}
        {%- endif %}
    - comment: {{ chain }}_{{ i }} {{ comment }}
      {%- endif %}

    {%- endfor %}
    {%- if chain_def %}

iptables_{{ chain }}_rule10000:
  iptables.append:
    - table: filter
    - match:
      - comment
    - comment: {{ chain }}_rule10000 Last Rule
    - chain: {{ chain }}
    - jump: DROP
    {%- endif %}
  {%- endfor %}

{%- endif %}
