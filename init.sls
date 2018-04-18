iptables:
  pkg.installed:
    - pkgs: [iptables, iptables-persistent]
  service.running:
    - name: netfilter-persistent
    - enable: true
