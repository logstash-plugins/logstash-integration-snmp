require 'logstash/devutils/rspec/spec_helper'
require 'logstash/inputs/snmptrap'
require 'logstash-integration-snmp_jars'
require 'timeout'
require 'socket'

describe LogStash::Inputs::Snmptrap, :integration => true do

  java_import 'org.logstash.snmp.SnmpTestTrapSender'
  java_import 'org.snmp4j.smi.OID'

  PDU_METADATA = '[@metadata][input][snmptrap][pdu]'

  let(:port) { rand(5000) + 1025 }
  let(:target_address) { "udp:localhost/#{port}" }
  let(:config) { { 'port' => port } }
  let(:plugin) { LogStash::Inputs::Snmptrap.new(config) }

  before(:all) do
    @trap_sender = org.logstash.snmp.SnmpTestTrapSender.new(0)
  end

  after(:all) do
    @trap_sender.close
  end

  describe 'traps receiver' do
    shared_examples 'a plugin receiving a v1 trap message' do
      it 'should process the message' do
        queue = run_plugin_and_get_queue(plugin) do
          @trap_sender.send_trap_v1(target_address, community, { '1.3.6.1.2.1.1.1.0' => 'It is a trap' })
        end

        expect(queue.size).to be(1)

        trap_event = queue.pop

        # fields
        expect(trap_event.get('iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0')).to eq('It is a trap')

        # metadata
        expect(trap_event.get("#{PDU_METADATA}[version]")).to eq('1')
        expect(trap_event.get("#{PDU_METADATA}[type]")).to eq('V1TRAP')
        expect(trap_event.get("#{PDU_METADATA}[enterprise]")).to eq('0.0')
        expect(trap_event.get("#{PDU_METADATA}[agent_addr]")).to eq('0.0.0.0')
        expect(trap_event.get("#{PDU_METADATA}[generic_trap]")).to eq(0)
        expect(trap_event.get("#{PDU_METADATA}[specific_trap]")).to eq(0)
        expect(trap_event.get("#{PDU_METADATA}[timestamp]")).to be(0)
        expect(trap_event.get("#{PDU_METADATA}[community]")).to eq(community)
        expect(trap_event.get("#{PDU_METADATA}[variable_bindings]")).to match hash_including('1.3.6.1.2.1.1.1.0' => 'It is a trap')
        expect(LogStash::Json.load(trap_event.get('message'))).to eq(trap_event.get("#{PDU_METADATA}"))
      end
    end

    shared_examples 'a plugin receiving a v2c or v3 trap message' do |version|
      it 'should process the message' do
        queue = run_plugin_and_get_queue(plugin) do
          bindings = { '1.3.6.1.2.1.1.1.0' => "It is a #{version} trap" }

          if version == '2c'
            @trap_sender.send_trap_v2c(target_address, 'public', bindings)
          else
            @trap_sender.send_trap_v3(target_address, security_name, auth_protocol, auth_pass, priv_protocol, priv_pass, security_level, bindings)
          end
        end

        expect(queue.size).to be(1)

        trap_event = queue.pop

        # fields
        expect(trap_event.get('iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0')).to eq("It is a #{version} trap" )

        # metadata
        expect(trap_event.get("#{PDU_METADATA}[version]")).to eq(version)
        expect(trap_event.get("#{PDU_METADATA}[type]")).to eq('TRAP')
        expect(trap_event.get("#{PDU_METADATA}[request_id]")).to be_a(Integer)
        expect(trap_event.get("#{PDU_METADATA}[error_status]")).to eq(0)
        expect(trap_event.get("#{PDU_METADATA}[error_status_text]")).to eq('Success')
        expect(trap_event.get("#{PDU_METADATA}[error_index]")).to eq(0)
        expect(trap_event.get("#{PDU_METADATA}[community]")).to eq('public') if version == '2c'
        expect(trap_event.get("#{PDU_METADATA}[variable_bindings]")).to match hash_including('1.3.6.1.2.1.1.1.0' => "It is a #{version} trap")
        expect(LogStash::Json.load(trap_event.get('message'))).to eq(trap_event.get("#{PDU_METADATA}"))
      end
    end

    context 'SNMP v1' do
      let(:config) { super().merge('supported_versions' => ['1']) }
      let(:community) { 'public' }

      context 'when receiving a message over TCP' do
        let(:target_address) { "tcp:127.0.0.1/#{port}" }
        let(:config) { super().merge('supported_transports' => ['tcp']) }

        it_behaves_like 'a plugin receiving a v1 trap message'
      end

      context 'when receiving a message over UDP' do
        let(:config) { super().merge('supported_transports' => ['udp']) }

        it_behaves_like 'a plugin receiving a v1 trap message'
      end

      context 'when receiving a message with unknown community' do
        let(:config) { super().merge('community' => "not-#{community}") }

        it 'should not receive a message' do
          queue = run_plugin_and_get_queue(plugin, timeout: 3) do
            @trap_sender.send_trap_v1(target_address, community, { '1.3.6.1.2.1.1.1.0' => 'It is a trap' })
          end

          expect(queue.size).to eq(0)
        end
      end
    end

    context 'SNMP v2c' do
      let(:community) { 'public' }

      context 'when receiving a message over UDP' do
        let(:config) { super().merge('supported_transports' => ['udp']) }

        it_behaves_like 'a plugin receiving a v2c or v3 trap message', '2c'
      end

      context 'when receiving a message over TCP' do
        let(:target_address) { "tcp:127.0.0.1/#{port}" }
        let(:config) { super().merge('supported_transports' => ['tcp']) }

        it_behaves_like 'a plugin receiving a v2c or v3 trap message', '2c'
      end

      context 'when receiving a message with unknown community' do
        let(:config) { super().merge('community' => "not-#{community}") }

        it 'should not process the message' do
          queue = run_plugin_and_get_queue(plugin, timeout: 3) do
            @trap_sender.send_trap_v2c(target_address, community, { '1.3.6.1.2.1.1.1.0' => 'It is a trap' })
          end

          expect(queue.size).to eq(0)
        end
      end
    end

    context 'SNMP v3' do
      let(:security_name) { 'user' }
      let(:auth_protocol) { 'md5' }
      let(:auth_pass) { 'foo@@Bar' }
      let(:priv_protocol) { 'aes' }
      let(:priv_pass) { 'bar@@Foo' }
      let(:security_level) { 'authPriv' }

      let(:config) do
        super().merge({
          'supported_versions' => ['3'],
          'security_name' => security_name,
          'auth_protocol' => auth_protocol,
          'auth_pass' => auth_pass,
          'priv_protocol' => priv_protocol,
          'priv_pass' => priv_pass,
          'security_level' => security_level
        })
      end

      context 'when receiving a message over UDP' do
        let(:config) { super().merge('supported_transports' => ['udp']) }

        it_behaves_like 'a plugin receiving a v2c or v3 trap message', '3'
      end

      context 'when receiving a message over TCP' do
        let(:target_address) { "tcp:127.0.0.1/#{port}" }
        let(:config) { super().merge('supported_transports' => ['tcp']) }

        it_behaves_like 'a plugin receiving a v2c or v3 trap message', '3'
      end

      context 'when receiving a request with invalid credentials' do
        it 'should not process the message' do
          queue = run_plugin_and_get_queue(plugin, timeout: 3) do
            @trap_sender.send_trap_v3(target_address, security_name, auth_protocol, 'wrong@password', priv_protocol, priv_pass, security_level, {'1.1' => 'foo'})
          end

          expect(queue.size).to eq(0)
        end
      end

      context 'when receiving a request with invalid security level' do
        it 'should not process the message' do
          queue = run_plugin_and_get_queue(plugin, timeout: 3) do
            @trap_sender.send_trap_v3(target_address, security_name, auth_protocol, auth_pass, priv_protocol, priv_pass, 'noAuthNoPriv', {'1.1' => 'foo'})
          end

          expect(queue.size).to eq(0)
        end
      end

      context 'when receiving a request with higher security level' do
        let(:security_level) { 'authNoPriv' }
        it 'should process the message' do
          queue = run_plugin_and_get_queue(plugin, timeout: 3) do
            @trap_sender.send_trap_v3(target_address, security_name, auth_protocol, auth_pass, priv_protocol, priv_pass, 'authPriv', {'1.1' => 'foo'})
          end

          expect(queue.size).to eq(1)
        end
      end
    end

    context 'with supported_versions' do
      context 'with multiple versions enabled' do
        let(:security_name) { 'user' }
        let(:auth_protocol) { 'md5' }
        let(:auth_pass) { 'foo@@Bar' }
        let(:priv_protocol) { 'aes' }
        let(:priv_pass) { 'bar@@Foo' }
        let(:security_level) { 'authPriv' }
        let(:config) do
          super().merge({
            'supported_versions' => %w[1 2c 3],
            'security_name' => security_name,
            'auth_protocol' => auth_protocol,
            'auth_pass' => auth_pass,
            'priv_protocol' => priv_protocol,
            'priv_pass' => priv_pass,
            'security_level' => security_level
          })
        end

        it 'should receive all messages' do
          queue = run_plugin_and_get_queue(plugin, messages: 4) do
            oid = '1.3.6.1.2.1.1.1.0'
            @trap_sender.send_trap_v1(target_address, 'public', { "#{oid}" => '1' })
            @trap_sender.send_trap_v1(target_address, 'public', { "#{oid}" => '1' })
            @trap_sender.send_trap_v2c(target_address, 'public', { "#{oid}" => '2c' })
            @trap_sender.send_trap_v3(target_address, security_name, auth_protocol, auth_pass, priv_protocol, priv_pass, security_level, { "#{oid}" => '3' })
          end

          expect(queue.size).to eq(4)

          events_per_version = queue.group_by { |event| event.get("#{PDU_METADATA}[version]") }
          expect(events_per_version['1'].size).to eq(2)
          expect(events_per_version['2c'].size).to eq(1)
          expect(events_per_version['3'].size).to eq(1)
        end
      end

      context 'with specific version enabled' do
        let(:config) { super().merge({ 'supported_versions' => ['1'] }) }

        it 'should not process unsupported message versions' do
          queue = run_plugin_and_get_queue(plugin, timeout: 3) do
            @trap_sender.send_trap_v2c(target_address, 'public', { '1' => 'foo' })
          end

          expect(queue.size).to eq(0)
        end
      end
    end

    context 'with oid_mapping_format => dotted_string' do
      let(:config) { super().merge({ 'oid_mapping_format' => 'dotted_string' }) }

      it 'should have OID fields mapped as dotted string' do
        event = run_plugin_and_get_queue(plugin) do
          @trap_sender.send_trap_v1(target_address, 'public', { '1.3.6.1.2.1.1.1.0' => '1.0' })
        end.pop

        expect(event.get('1.3.6.1.2.1.1.1.0')).to eq('1.0')
      end
    end

    context 'with oid_mapping_format => ruby_snmp' do
      let(:config) { super().merge({ 'oid_mapping_format' => 'ruby_snmp', 'use_provided_mibs' => false }) }

      it 'should have OID fields mapped as dotted string' do
        event = run_plugin_and_get_queue(plugin) do
          @trap_sender.send_trap_v1(target_address, 'public', { '1.3.6.1.2.1.1.1.0' => '1.0' })
        end.pop

        expect(event.get('SNMPv2-MIB::sysDescr.0')).to eq('1.0')
      end
    end

    context 'with oid_map_field_values' do
      context 'set to false' do
        let(:config) { super().merge('oid_map_field_values' => false) }

        it 'should not map OID field values' do
          event = run_plugin_and_get_queue(plugin) do
            @trap_sender.send_trap_v2c(target_address, 'public', { '1.3.6.1.2.1.1.2.0' => org.snmp4j.smi.OID.new('1.3.6.1.4.1.8072.3.2.10') })
          end.pop

          expect(event).to be_a(LogStash::Event)
          expect(event.get('iso.org.dod.internet.mgmt.mib-2.system.sysObjectID.0')).to eq('1.3.6.1.4.1.8072.3.2.10')
        end
      end

      context 'set to true' do
        let(:config) { super().merge('oid_map_field_values' => true) }

        it 'should map OID field values' do
          event = run_plugin_and_get_queue(plugin) do
            @trap_sender.send_trap_v2c(target_address, 'public', { '1.3.6.1.2.1.1.2.0' => org.snmp4j.smi.OID.new('1.3.6.1.4.1.8072.3.2.10') })
          end.pop

          expect(event).to be_a(LogStash::Event)
          expect(event.get('iso.org.dod.internet.mgmt.mib-2.system.sysObjectID.0')).to eq('iso.org.dod.internet.private.enterprises.8072.3.2.10')
        end
      end
    end

    context 'with no MIBs provided' do
      let(:config) { super().reject { |key, _| key == 'mib_paths' }.merge('use_provided_mibs' => false, 'oid_mapping_format' => 'ruby_snmp') }

      it 'should load default ruby-snmp MIBs' do
        event = run_plugin_and_get_queue(plugin) do
          bindings = {
            '1.3.6.1.2.1.1.2.0' => 'SNMPv2-SMI.dic',
            '1.3' => 'SNMPv2-MIB.dic',
            '1.3.6.1.2.1.2.1' => 'IF-MIB.dic',
            '1.3.6.1.2.1.4' => 'IP-MIB.dic',
            '1.3.6.1.2.1.6' => 'TCP-MIB.dic',
            '1.3.6.1.2.1.7.1' => 'UDP-MIB.dic',
            # non-default ACCOUNTING-CONTROL-MIB::accountingControlMIB
            '1.3.6.1.2.1.60' => 'ACCOUNTING-CONTROL-MIB.dic'
          }

          @trap_sender.send_trap_v2c(target_address, 'public', bindings)
        end.pop

        expect(event).to be_a(LogStash::Event)
        expect(event.get('SNMPv2-SMI::org')).to_not be_nil
        expect(event.get('SNMPv2-MIB::sysObjectID.0')).to_not be_nil
        expect(event.get('IF-MIB::ifNumber')).to_not be_nil
        expect(event.get('IP-MIB::ip')).to_not be_nil
        expect(event.get('TCP-MIB::tcp')).to_not be_nil
        expect(event.get('UDP-MIB::udpInDatagrams')).to_not be_nil
        expect(event.get('SNMPv2-SMI::mib-2.60')).to_not be_nil
      end
    end

    context 'with host' do
      context 'set to IP address' do
        let(:ip_address) { IPSocket.getaddress(Socket.gethostname) }
        let(:config) { super().merge('host' => ip_address, 'oid_mapping_format' => 'dotted_string')}

        it "should only received message through configured host" do
          queue = run_plugin_and_get_queue(plugin, messages: 2, timeout: 5) do
            @trap_sender.send_trap_v2c("udp:#{ip_address}/#{port}", 'public', { '1.3.6.1.2.1.1.2.0' => ip_address })
            @trap_sender.send_trap_v2c("udp:127.0.0.1/#{port}", 'public', { '1.3.6.1.2.1.1.2.0' => 'INVALID' })
          end

          expect(queue.size).to eq(1)
          expect(queue.pop.get('1.3.6.1.2.1.1.2.0')).to eq(ip_address)
        end
      end

      context 'set to any IPV6 address' do
        let(:config) { super().merge('host' => '::', 'oid_mapping_format' => 'dotted_string') }

        it "should received message through localhost" do
          queue = run_plugin_and_get_queue(plugin, messages: 2, timeout: 5) do
            @trap_sender.send_trap_v2c("udp:localhost/#{port}", 'public', { '1.3.6.1.2.1.1.2.0' => 'IPV6' })
          end

          expect(queue.size).to eq(1)
          expect(queue.pop.get('1.3.6.1.2.1.1.2.0')).to eq('IPV6')
        end
      end
    end
  end

  def run_plugin_and_get_queue(plugin, timeout: 30, register: true, messages: 1, &actions)
    plugin.register if register

    message_latch = Concurrent::CountDownLatch.new(messages)
    allow(plugin).to receive(:consume_trap_message).and_wrap_original do |original_method, *args, &block|
      original_method.call(*args, &block)
      message_latch.count_down
    end

    Thread.new do
      Timeout::timeout(5) do
        until plugin.client_listening?
          sleep 0.2
        end
      end

      begin
        actions.call
        message_latch.wait(timeout)
      ensure
        plugin.do_close
        plugin.do_stop
      end
    end

    queue = Concurrent::Array.new
    plugin.run(queue)
    queue
  end
end