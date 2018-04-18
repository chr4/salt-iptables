{% for v in ['ipv4', 'ipv6'] %}
input_policy_{{v}}:
  iptables.set_policy: [table: filter, family: {{v}}, chain: INPUT, policy: DROP, save: true]
output_policy_{{v}}:
  iptables.set_policy: [table: filter, family: {{v}}, chain: OUTPUT, policy: DROP, save: true]
forward_policy_{{v}}:
  iptables.set_policy: [table: filter, family: {{v}}, chain: FORWARD, policy: DROP, save: true]

input_drop_invalid_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: INPUT, jump: DROP, match: conntrack, ctstate: 'INVALID', save: true]

input_allow_lo_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: INPUT, jump: ACCEPT, in-interface: lo, save: true]

input_allow_related_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: INPUT, jump: ACCEPT, match: conntrack, ctstate: 'RELATED,ESTABLISHED', save: true]

input_drop_syn_for_established_connection_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: INPUT, jump: DROP, proto: tcp, match: conntrack, ctstate: 'ESTABLISHED', tcp-flags: SYN SYN, save: true]

{% if v == 'ipv4' %}
input_drop_icmp_timestamp_request_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: INPUT, jump: DROP, proto: icmp, icmp-type: timestamp-request, save: true]

input_drop_icmp_timestamp_reply_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: INPUT, jump: DROP, proto: icmp, icmp-type: timestamp-reply, save: true]

input_accept_icmp_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: INPUT, jump: ACCEPT, proto: icmp, save: true]

input_reject_with_icmp_admin_prohibited_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: INPUT, jump: REJECT, reject-with: icmp-admin-prohibited, save: true]
{% endif %}

{% if v == 'ipv6' %}
input_accept_icmp_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: INPUT, jump: ACCEPT, proto: icmpv6, save: true]

input_reject_with_tcp_reset_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: INPUT, jump: REJECT, proto: tcp, reject-with: tcp-reset, save: true]

input_reject_with_icmp6_adm_prohibited_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: INPUT, jump: REJECT, reject-with: icmp6-adm-prohibited, save: true]
{% endif %}

output_drop_invalid_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: OUTPUT, jump: DROP, match: conntrack, ctstate: 'INVALID', save: true]

output_allow_related_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: OUTPUT, jump: ACCEPT, match: conntrack, ctstate: 'RELATED,ESTABLISHED', save: true]

output_allow_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: OUTPUT, jump: ACCEPT, save: true]

forward_drop_invalid_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: FORWARD, jump: DROP, match: conntrack, ctstate: 'INVALID', save: true]

forward_allow_related_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: FORWARD, jump: ACCEPT, match: conntrack, ctstate: 'RELATED,ESTABLISHED', save: true]

forward_allow_{{v}}:
  iptables.append: [table: filter, family: {{v}}, chain: FORWARD, jump: ACCEPT, save: true]
{% endfor %}
