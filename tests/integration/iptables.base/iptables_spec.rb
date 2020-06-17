control 'iptables' do
  title 'should be installed and have base rules configured'

  describe package('iptables') do
    it { should be_installed }
  end

  describe package('iptables-persistent') do
    it { should be_installed }
  end

  describe service('netfilter-persistent') do
    it { should be_enabled }
  end

  # ipv4
  describe iptables(table:'filter', chain: 'INPUT') do
    it { should have_rule('-P INPUT DROP') }
  end

  describe iptables(table:'filter', chain: 'OUTPUT') do
    it { should have_rule('-P OUTPUT DROP') }
  end

  describe iptables(table:'filter', chain: 'FORWARD') do
    it { should have_rule('-P FORWARD DROP') }
  end

  describe iptables do
    it { should have_rule('-A INPUT -m conntrack --ctstate INVALID -j DROP') }
    it { should have_rule('-A INPUT -i lo -j ACCEPT') }
    it { should have_rule('-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT') }
    it { should have_rule('-A INPUT -p tcp -m conntrack --ctstate ESTABLISHED -m tcp --tcp-flags SYN SYN -j DROP') }
    it { should have_rule('-A INPUT -p tcp -m state --state NEW -m tcp --sport 1025:65535 --dport 22 -j ACCEPT') }
    it { should have_rule('-A INPUT -p tcp -m state --state NEW -m tcp --sport 1025:65535 -m multiport --dports 80,443 -j ACCEPT') }
    it { should have_rule('-A INPUT -p icmp -m icmp --icmp-type 13 -j DROP') }
    it { should have_rule('-A INPUT -p icmp -m icmp --icmp-type 14 -j DROP') }
    it { should have_rule('-A INPUT -p icmp -j ACCEPT') }
    it { should have_rule('-A INPUT -j REJECT --reject-with icmp-admin-prohibited') }
    it { should have_rule('-A FORWARD -m conntrack --ctstate INVALID -j DROP') }
    it { should have_rule('-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT') }
    it { should have_rule('-A FORWARD -j ACCEPT') }
    it { should have_rule('-A OUTPUT -m conntrack --ctstate INVALID -j DROP') }
    it { should have_rule('-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT') }
    it { should have_rule('-A OUTPUT -j ACCEPT') }
  end

  # ipv6
  describe ip6tables(table:'filter', chain: 'INPUT') do
    it { should have_rule('-P INPUT DROP') }
  end

  describe ip6tables(table:'filter', chain: 'OUTPUT') do
    it { should have_rule('-P OUTPUT DROP') }
  end

  describe ip6tables(table:'filter', chain: 'FORWARD') do
    it { should have_rule('-P FORWARD DROP') }
  end

  describe ip6tables do
    it { should have_rule('-A INPUT -m conntrack --ctstate INVALID -j DROP') }
    it { should have_rule('-A INPUT -i lo -j ACCEPT') }
    it { should have_rule('-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT') }
    it { should have_rule('-A INPUT -p tcp -m conntrack --ctstate ESTABLISHED -m tcp --tcp-flags SYN SYN -j DROP') }
    it { should have_rule('-A INPUT -p tcp -m state --state NEW -m tcp --sport 1025:65535 --dport 22 -j ACCEPT') }
    it { should have_rule('-A INPUT -p tcp -m state --state NEW -m tcp --sport 1025:65535 -m multiport --dports 80,443 -j ACCEPT') }
    it { should have_rule('-A INPUT -p ipv6-icmp -j ACCEPT') }
    it { should have_rule('-A INPUT -p tcp -j REJECT --reject-with tcp-reset') }
    it { should have_rule('-A INPUT -j REJECT --reject-with icmp6-adm-prohibited') }
    it { should have_rule('-A FORWARD -m conntrack --ctstate INVALID -j DROP') }
    it { should have_rule('-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT') }
    it { should have_rule('-A FORWARD -j ACCEPT') }
    it { should have_rule('-A OUTPUT -m conntrack --ctstate INVALID -j DROP') }
    it { should have_rule('-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT') }
    it { should have_rule('-A OUTPUT -j ACCEPT') }
  end
end
