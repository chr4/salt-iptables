control 'iptables' do
  title 'should be installed'

  describe package('iptables') do
    it { should be_installed }
  end

  describe package('iptables-persistent') do
    it { should be_installed }
  end

  describe service('netfilter-persistent') do
    it { should be_enabled }
  end
end
