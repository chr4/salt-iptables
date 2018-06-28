{% for name, rule in pillar['iptables'].items() %}
{% for v in [4, 6] %}
{{ name }}_iptables_ipv{{v}}:
  iptables.insert:
    - position: 5
    - family: ipv{{v}}
    - save: true
{% for key, value in rule.items() %}
    - {{ key }}: {{ value }}
{% endfor -%}
{% endfor -%}
{% endfor -%}
