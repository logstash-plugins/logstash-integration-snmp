require 'logstash/devutils/rspec/spec_helper'
require 'logstash/inputs/snmp'

describe LogStash::Inputs::Snmp, :integration => true do
  let(:config) { {} }
  let(:plugin) { LogStash::Inputs::Snmp.new(config) }

  shared_examples 'snmp plugin return one udp event and one tcp event' do |config|
    it 'should have one udp from snmp1 and one tcp from snmp2' do
      events = input(config) { |_, queue| 2.times.collect { queue.pop } }
      udp = 0; tcp = 0
      events.each do |event|
        if event.get('[@metadata][host_protocol]') == 'udp'
          udp += 1
          expect(event.get('[@metadata][host_protocol]')).to eq('udp')
          expect(event.get('[@metadata][host_address]')).to eq('snmp1')
          expect(event.get('[@metadata][host_port]')).to eq('161')
        else
          tcp += 1
          expect(event.get('[@metadata][host_protocol]')).to eq('tcp')
          expect(event.get('[@metadata][host_address]')).to eq('snmp2')
          expect(event.get('[@metadata][host_port]')).to eq('162')
        end
      end
      expect(udp).to eq(1)
      expect(tcp).to eq(1)
    end
  end

  describe '`get` operation' do
    let(:config) do
      super().merge({ 'get' => ['1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.7.0', '1.3.6.1.2.1.1.5.0'], 'ecs_compatibility' => 'disabled' })
    end

    shared_examples 'snmp plugin return single get event' do
      it 'should have OID fields' do
        event = run_plugin_and_get_queue(plugin).pop
        expect(event).to be_a(LogStash::Event)
        expect(event.get('iso.org.dod.internet.mgmt.mib-2.system.sysServices.0')).to be_a Integer
        expect(event.get('iso.org.dod.internet.mgmt.mib-2.system.sysName.0')).to be_a String
        expect(event.get('iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0')).to be_a String
      end
    end

    describe 'against single snmp server with snmp v1' do
      let(:config) { super().merge({ 'hosts' => [{ 'host' => 'udp:snmp1/161', 'version' => '1', 'community' => 'public' }] }) }
      it_behaves_like 'snmp plugin return single get event'
    end

    describe 'against single snmp server with snmp v2' do
      let(:config) { super().merge({ 'hosts' => [{ 'host' => 'udp:snmp1/161', 'version' => '2c', 'community' => 'public' }] }) }
      it_behaves_like 'snmp plugin return single get event'
    end

    describe 'against single server with snmp v3' do
      let(:config) do
        super().merge(
          'hosts' => [{ 'host' => "tcp:snmp1/161", 'version' => '3' }],
          'security_name' => 'user_1',
          'auth_protocol' => 'sha',
          'auth_pass' => 'STrP@SSPhr@sE',
          'priv_protocol' => 'aes',
          'priv_pass' => 'STr0ngP@SSWRD161',
          'security_level' => 'authPriv'
        )
      end

      it_behaves_like 'snmp plugin return single get event'
    end
  end

  describe '`walk` operation' do
    let(:config) do
      super().merge({ 'walk' => %w[1.3.6.1.2.1.1.9.1.4], 'ecs_compatibility' => 'disabled' })
    end

    shared_examples 'snmp plugin return single walk event' do
      it 'should have OID fields' do
        event = run_plugin_and_get_queue(plugin).pop
        expect(event).to be_a(LogStash::Event)
        (1..10).each do |index|
          expect(event.get("iso.org.dod.internet.mgmt.mib-2.system.sysORTable.sysOREntry.sysORUpTime.#{index}")).to be_a Integer
        end
      end
    end

    describe 'against single snmp server with snmp v1' do
      let(:config) { super().merge({ 'hosts' => [{ 'host' => 'udp:snmp1/161', 'version' => '1', 'community' => 'public' }] }) }
      it_behaves_like 'snmp plugin return single walk event'
    end

    describe 'against single snmp server with snmp v2' do
      let(:config) { super().merge({ 'hosts' => [{ 'host' => 'udp:snmp1/161', 'version' => '2c', 'community' => 'public' }] }) }
      it_behaves_like 'snmp plugin return single walk event'
    end

    describe 'against single server with snmp v3' do
      let(:config) do
        super().merge(
          'hosts' => [{ 'host' => "tcp:snmp1/161", 'version' => '3' }],
          'security_name' => 'user_1',
          'auth_protocol' => 'sha',
          'auth_pass' => 'STrP@SSPhr@sE',
          'priv_protocol' => 'aes',
          'priv_pass' => 'STr0ngP@SSWRD161',
          'security_level' => 'authPriv'
        )
      end

      it_behaves_like 'snmp plugin return single walk event'
    end
  end

  describe '`table` operation' do
    let(:config) do
      super().merge({ 'tables' =>  [{ 'name' => 'sysORUpTimeTable', 'columns' => ['1.3.6.1.2.1.1.9.1.4'] }], 'ecs_compatibility' => 'disabled' })
    end

    shared_examples 'snmp plugin return single table event' do
      it 'should have OID fields' do
        event = run_plugin_and_get_queue(plugin).pop
        expect(event).to be_a(LogStash::Event)
        table = event.get('sysORUpTimeTable')
        expect(table).to be_a(Array)

        (0..9).each do |index|
          expect(table[index]["iso.org.dod.internet.mgmt.mib-2.system.sysORTable.sysOREntry.sysORUpTime.#{index + 1}"]).to be_a Integer
          expect(table[index]['index']).to be_a(String)
        end
      end
    end

    describe 'against single snmp server with snmp v1' do
      let(:config) { super().merge({ 'hosts' => [{ 'host' => 'udp:snmp1/161', 'version' => '1', 'community' => 'public' }] }) }
      it_behaves_like 'snmp plugin return single table event'
    end

    describe 'against single snmp server with snmp v2' do
      let(:config) { super().merge({ 'hosts' => [{ 'host' => 'udp:snmp1/161', 'version' => '2c', 'community' => 'public' }] }) }
      it_behaves_like 'snmp plugin return single table event'
    end

    describe 'against single server with snmp v3' do
      let(:config) do
        super().merge(
          'hosts' => [{ 'host' => "tcp:snmp1/161", 'version' => '3' }],
          'security_name' => 'user_1',
          'auth_protocol' => 'sha',
          'auth_pass' => 'STrP@SSPhr@sE',
          'priv_protocol' => 'aes',
          'priv_pass' => 'STr0ngP@SSWRD161',
          'security_level' => 'authPriv'
        )
      end

      it_behaves_like 'snmp plugin return single table event'
    end
  end

  describe 'multiple operations' do
    let(:config) do
      super().merge({
        'get' => %w[1.3.6.1.2.1.1.1.0],
        'walk' => %w[1.3.6.1.2.1.1.9.1.4],
        'tables' =>  [{ 'name' => 'sysORUpTimeTable', 'columns' => %w[1.3.6.1.2.1.1.5] }],
        'ecs_compatibility' => 'disabled'
      })
    end

    shared_examples 'snmp plugin return single multi-operations event' do
      it 'should have OID fields' do
        event = run_plugin_and_get_queue(plugin).pop
        expect(event).to be_a(LogStash::Event)

        # get
        expect(event.get('iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0')).to be_a String

        # walk
        (1..10).each do |index|
          expect(event.get("iso.org.dod.internet.mgmt.mib-2.system.sysORTable.sysOREntry.sysORUpTime.#{index}")).to be_a Integer
        end

        # table
        table = event.get('sysORUpTimeTable')
        expect(table).to be_a(Array)
        expect(table.length).to be(1)

        table_oid_data = table[0]
        expect(table_oid_data['iso.org.dod.internet.mgmt.mib-2.system.sysName.0']).to be_a String
        expect(table_oid_data['index']).to be_a String
      end
    end

    describe 'against single snmp server with snmp v1' do
      let(:config) { super().merge({ 'hosts' => [{ 'host' => 'udp:snmp1/161', 'version' => '1', 'community' => 'public' }] }) }
      it_behaves_like 'snmp plugin return single multi-operations event'
    end

    describe 'against single snmp server with snmp v2' do
      let(:config) { super().merge({ 'hosts' => [{ 'host' => 'udp:snmp1/161', 'version' => '2c', 'community' => 'public' }] }) }
      it_behaves_like 'snmp plugin return single multi-operations event'
    end

    describe 'against single server with snmp v3' do
      let(:config) do
        super().merge(
          'hosts' => [{ 'host' => "tcp:snmp1/161", 'version' => '3' }],
          'security_name' => 'user_1',
          'auth_protocol' => 'sha',
          'auth_pass' => 'STrP@SSPhr@sE',
          'priv_protocol' => 'aes',
          'priv_pass' => 'STr0ngP@SSWRD161',
          'security_level' => 'authPriv'
        )
      end

      it_behaves_like 'snmp plugin return single multi-operations event'
    end
  end

  describe 'single input plugin on single server with snmp v2 and mix of udp and tcp' do
    let(:config) do
      super().merge(
        'get' => %w[1.3.6.1.2.1.1.1.0],
        'hosts' => [{ 'host' => 'udp:snmp1/161', 'community' => 'public' }, { 'host' => 'tcp:snmp1/161', 'community' => 'public' }]
      )
    end

    it 'should return two events ' do
      queue = run_plugin_and_get_queue(plugin)
      host_cnt_snmp1 = queue.select { |event| event.get('host') == 'snmp1' }.size
      expect(queue.size).to eq(2)
      expect(host_cnt_snmp1).to eq(2)
    end
  end

  describe 'single input plugin on multiple udp hosts' do
    let(:config) do
      super().merge({
        'get' => %w[1.3.6.1.2.1.1.1.0],
        'hosts' => [{ 'host' => 'udp:snmp1/161', 'community' => 'public' }, { 'host' => 'udp:snmp2/162', 'community' => 'public' }]
      })
    end

    it 'should return two events, one per host' do
      queue = run_plugin_and_get_queue(plugin)
      hosts = queue.map { |event| event.get('host') }.sort
      expect(queue.size).to eq(2)
      expect(hosts).to eq(['snmp1', 'snmp2'])
    end
  end

  describe 'multiple pipelines and mix of udp and tcp hosts' do
    let(:config) { { 'get' => ['1.3.6.1.2.1.1.1.0'], 'hosts' => [{ 'host' => 'udp:snmp1/161', 'community' => 'public' }], 'ecs_compatibility' => 'disabled' } }
    let(:config2) { { 'get' => ['1.3.6.1.2.1.1.1.0'], 'hosts' => [{ 'host' => 'tcp:snmp2/162', 'community' => 'public' }], 'ecs_compatibility' => 'disabled' } }
    let(:plugin) { LogStash::Inputs::Snmp.new(config) }
    let(:plugin2) { LogStash::Inputs::Snmp.new(config2) }

    it 'should return two events, one per host' do
      queue = run_plugin_and_get_queue(plugin)
      queue2 = run_plugin_and_get_queue(plugin2)
      hosts = [queue.pop, queue2.pop].map { |event| event.get('host') }.sort
      expect(hosts).to eq(%w[snmp1 snmp2])
    end
  end

  describe 'multiple plugin inputs and mix of udp and tcp hosts' do
    config = <<-CONFIG
        input {
          snmp {
            get => ["1.3.6.1.2.1.1.1.0"]
            hosts => [{host => "udp:snmp1/161" community => "public"}]
            ecs_compatibility => "disabled"
          }
          snmp {
            get => ["1.3.6.1.2.1.1.1.0"]
            hosts => [{host => "tcp:snmp2/162" community => "public"}]
            ecs_compatibility => "disabled"
          }
        }
    CONFIG

    it_behaves_like 'snmp plugin return one udp event and one tcp event', config
  end

  describe 'two plugins on different hosts with snmp v3 with same security name with different credentials and mix of udp and tcp' do
    config = <<-CONFIG
        input {
          snmp {
            get => ["1.3.6.1.2.1.1.1.0"]
            hosts => [{host => "udp:snmp1/161" version => "3"}]
            security_name => "user_1"
            auth_protocol => "sha"
            auth_pass => "STrP@SSPhr@sE"
            priv_protocol => "aes"
            priv_pass => "STr0ngP@SSWRD161"
            security_level => "authPriv"
            ecs_compatibility => "disabled"
          }
          snmp {
            get => ["1.3.6.1.2.1.1.1.0"]
            hosts => [{host => "tcp:snmp2/162" version => "3"}]
            security_name => "user_1"
            auth_protocol => "sha"
            auth_pass => "STrP@SSPhr@sE"
            priv_protocol => "aes"
            priv_pass => "STr0ngP@SSWRD162"
            security_level => "authPriv"
            ecs_compatibility => "disabled"
          }
        }
    CONFIG

    it_behaves_like 'snmp plugin return one udp event and one tcp event', config
  end

  describe 'single host with tcp over ipv6' do
    let(:config) do
      super().merge({ 'get' => %w[1.3.6.1.2.1.1.1.0], 'hosts' => [{ 'host' => 'tcp:[2001:3984:3989::161]/161' }] })
    end

    it 'should fetch an event' do
      event = run_plugin_and_get_queue(plugin).pop
      expect(event).to be_a(LogStash::Event)
    end
  end

  describe 'single input plugin with oid_mapping_format => dotted_string' do
    let(:config) do
      super().merge({
        'get' => %w[1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.7.0 1.3.6.1.2.1.1.5.0],
        'oid_mapping_format' => 'dotted_string',
        'hosts' => [{ 'host' => 'udp:snmp1/161', 'version' => '2c', 'community' => 'public' }]
      })
    end

    it 'should have OID fields mapped as dotted string' do
      event = run_plugin_and_get_queue(plugin).pop
      expect(event).to be_a(LogStash::Event)
      expect(event.get('1.3.6.1.2.1.1.1.0')).to be_a String
      expect(event.get('1.3.6.1.2.1.1.7.0')).to be_a Integer
      expect(event.get('1.3.6.1.2.1.1.5.0')).to be_a String
    end
  end

  describe 'single input plugin with oid_mapping_format => ruby_snmp' do
    let(:config) do
      super().merge({
        'get' => %w[1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.7.0 1.3.6.1.2.1.1.5.0],
        'oid_mapping_format' => 'ruby_snmp',
        'hosts' => [{ 'host' => 'udp:snmp1/161', 'version' => '2c', 'community' => 'public' }]
      })
    end

    it 'should have OID fields mapped as ruby snmp' do
      event = run_plugin_and_get_queue(plugin).pop
      expect(event).to be_a(LogStash::Event)
      expect(event.get('SNMPv2-MIB::sysDescr.0')).to be_a String
      expect(event.get('SNMPv2-MIB::sysServices.0')).to be_a Integer
      expect(event.get('SNMPv2-MIB::sysName.0')).to be_a String
    end
  end

  def run_plugin_and_get_queue(plugin, timeout: 30, register: true)
    poll_clients_latch = Concurrent::CountDownLatch.new(1)

    allow(plugin).to receive(:poll_clients).and_wrap_original do |original_method, *args, &block|
      original_method.call(*args, &block)
      poll_clients_latch.count_down
    end

    plugin.register if register
    Thread.new do
      poll_clients_latch.wait(timeout)
    ensure
      plugin.do_close
      plugin.do_stop
    end

    queue = []
    plugin.run(queue)
    queue
  end
end
