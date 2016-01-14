strongswan:
  pkg:
    - installed

strongswan-ikev1:
  pkg:
    - installed

strongswan-plugin-pubkey:
  pkg:
    - installed

strongswan-plugin-ipseckey:
  pkg:
    - installed

/etc/ipsec.conf:
  file.managed:
    - user: root
    - group: root
    - mode: 644
    - template: jinja
    - source: salt://firewall/files/ipsec/ipsec.conf

/etc/ipsec.secrets:
  file.managed:
    - user: root
    - group: root
    - mode: 644
    - template: jinja
    - source: salt://firewall/files/ipsec/ipsec.secrets

