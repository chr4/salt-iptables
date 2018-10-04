{% for name, rule in pillar['iptables']|dictsort %}
{% for v in [4, 6] %}
{{ name }}_iptables_ipv{{v}}:
  iptables.append:
    - family: ipv{{v}}
    - save: true
{% for key, value in rule|dictsort %}
    - {{ key }}: {{ value }}
{% endfor -%}
{% endfor -%}
{% endfor -%}
