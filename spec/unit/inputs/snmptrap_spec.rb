require "logstash/devutils/rspec/spec_helper"
require "logstash/devutils/rspec/shared_examples"
require 'logstash/plugin_mixins/ecs_compatibility_support/spec_helper'
require_relative '../../../lib/logstash/inputs/snmptrap'
require 'logstash-integration-snmp_jars'

describe LogStash::Inputs::Snmptrap, :ecs_compatibility_support do

  java_import 'org.logstash.snmp.trap.SnmpTrapMessage'
  java_import 'org.snmp4j.smi.IpAddress'

  let(:mock_target) { double("org.snmp4j.Target") }
  let(:mock_client) { double("org.logstash.snmp.SnmpClient") }
  let(:config) { Hash.new }
  let(:source_ip) { '192.168.1.11' }

  subject(:plugin) { described_class.new(config) }

  context "an interruptible input plugin" do
    context "#stop" do
      let(:queue) { SizedQueue.new(20) }

      before(:each) do
        plugin.register
      end

      it "returns from run" do
        Thread.new(queue) { |queue| loop { queue.pop } }

        plugin_thread = Thread.new(plugin, queue) { |subject, queue| subject.run(queue) }
        sleep 0.5
        expect(plugin_thread).to be_alive

        plugin.do_stop
        plugin.do_close
        wait(3).for { plugin_thread }.to_not be_alive
      end
    end
  end

  ecs_compatibility_matrix(:disabled, :v1, :v8) do |ecs_select|

    let(:config) { super().merge 'ecs_compatibility' => ecs_select.active_mode }

    context 'with an SNMP v1 trap' do

      let(:trap) do
        bindings = {
          "1.3.6.1.2.3.4" => 111
        }

        trap_event = {
          "enterprise" =>  "enterprises.9",
          "agent_addr" => source_ip,
          "specific_trap" => 42,
          "timestamp" => 12345,
          "variable_bindings" => bindings
        }

        trap = org.logstash.snmp.trap.SnmpTrapMessage.new(0, 'public'.bytes, org.snmp4j.smi.IpAddress.new(source_ip), trap_event, bindings)
        trap
      end

      before { @event = plugin.send :process_trap_message, trap }

      it "extract snmp payload" do
        expect( @event.get('message') ).to be_a String
        expect( @event.get('1.3.6.1.2.3.4') ).to eql 111
      end

      it "sets source host" do
        if ecs_select.active_mode == :disabled
          expect( @event.get('host') ).to eql source_ip
        else
          expect( @event.get('host') ).to eql 'ip' => source_ip
        end
      end

    end

    context 'with an SNMP v2 trap' do

      let(:trap) do
        bindings = {
          "1.2.3" => "foo",
          "1.4.5.6" => "bar",
        }

        trap_event = {
          "request_id" => 12345,
          "error_status" => 0,
          "timestamp" => 1011,
          "variable_bindings" => bindings
        }

        trap = org.logstash.snmp.trap.SnmpTrapMessage.new(1, 'public'.bytes, org.snmp4j.smi.IpAddress.new(source_ip), trap_event, bindings)
        trap
      end

      before { @event = plugin.send :process_trap_message, trap }

      it "extract snmp payload" do
        expect( @event.get('message') ).to be_a String
        expect( @event.get('1.2.3') ).to eql 'foo'
        expect( @event.get('1.4.5.6') ).to eql 'bar'
      end

      it "sets source host" do
        if ecs_select.active_mode == :disabled
          expect( @event.get('host') ).to eql source_ip
        else
          expect( @event.get('host') ).to eql 'ip' => source_ip
        end
      end

      context 'with target' do

        let(:config) { super().merge 'target' => '[snmp]' }

        it "extract snmp payload" do
          expect( @event.include?('1.2.3') ).to be false
          expect( @event.include?('1.3.6.1.2.1.1.3.0') ).to be false
          expect( @event.get('[snmp][1.2.3]') ).to eql 'foo'

          expect( @event.get('message') ).to be_a String
        end

        it "sets source host" do
          if ecs_select.active_mode == :disabled
            expect( @event.get('host') ).to eql source_ip
          else
            expect( @event.get('host') ).to eql 'ip' => source_ip
          end
        end

      end

    end

  end
end
