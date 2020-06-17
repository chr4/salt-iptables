control 'iptables' do
  title 'should be installed and pillar rules configured'

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
    it { should have_rule('-P INPUT ACCEPT') }
  end

  describe iptables do
    it { should have_rule('-A INPUT -p tcp -m state --state NEW -m tcp --sport 1025:65535 --dport 22 -j ACCEPT') }
    it { should have_rule('-A INPUT -p tcp -m state --state NEW -m tcp --sport 1025:65535 -m multiport --dports 80,443 -j ACCEPT') }
  end

  # ipv6
  describe ip6tables(table:'filter', chain: 'INPUT') do
    it { should have_rule('-P INPUT ACCEPT') }
  end

  describe ip6tables do
    it { should have_rule('-A INPUT -p tcp -m state --state NEW -m tcp --sport 1025:65535 --dport 22 -j ACCEPT') }
    it { should have_rule('-A INPUT -p tcp -m state --state NEW -m tcp --sport 1025:65535 -m multiport --dports 80,443 -j ACCEPT') }
  end
end
