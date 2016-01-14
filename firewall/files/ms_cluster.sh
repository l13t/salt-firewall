#!/bin/bash

# {{ salt['pillar.get']('do-not-touch-msg') }}

status=$1
to_do="add"
if [ "0$status" = "0primary" ]
then
  to_do="del"
fi
{%- for ip in salt['pillar.get']('keepalived:keepalived:ext_vip:ip') %}
/etc/keepalived/bypass_ipvs.sh $to_do {{ ip }}
{%- endfor %}
/etc/conntrackd/primary-backup.sh $status
