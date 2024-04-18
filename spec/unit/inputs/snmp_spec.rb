# encoding: utf-8
require 'rspec/wait'
require "logstash/devutils/rspec/spec_helper"
require 'logstash/plugin_mixins/ecs_compatibility_support/spec_helper'
require_relative '../../../lib/logstash/inputs/snmp'

describe LogStash::Inputs::Snmp, :ecs_compatibility_support do
  let(:mock_target) { double("org.snmp4j.Target") }
  let(:mock_client) { double("org.logstash.snmp.SnmpClient") }
  let(:config) {{}}

  subject(:plugin) { described_class.new(config) }

  context "an interruptible input plugin" do
    let(:config) {{ "get" => ["1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "community" => "public"}] }}

    context "#stop" do
      let(:queue) { SizedQueue.new(20) }

      before(:each) do
        allow(plugin).to receive(:build_client!).and_return(mock_client)
        allow(mock_client).to receive(:listen)
        allow(mock_client).to receive(:create_target).and_return(mock_target)
        expect(mock_client).to receive(:get).and_return({})
        expect(mock_client).to receive(:close)

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

  context "OIDs options validation" do
    valid_configs = [
            {"get" => ["1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
            {"get" => [".1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
            {"get" => [".1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}], "oid_root_skip" => 2},
            {"get" => [".1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}], "oid_path_length" => 2},
            {"get" => ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
            {"get" => ["1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
            {"walk" => ["1.3.6.1.2.1.1.1"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
            {"tables" => [{"name" => "ltmPoolStatTable", "columns" => ["1.3.6.1.4.1.3375.2.2.5.2.3.1.1", "1.3.6.1.4.1.3375.2.2.5.2.3.1.6"]}], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
    ]

    invalid_configs = [
          {"get" => ["1.3.6.1.2.1.1.1.a"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"get" => ["test"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"get" => [], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"get" => "foo", "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"get" => [".1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}], "oid_path_length" => "a" },
          {"get" => [".1.3.6.1.2.1.1.1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}], "oid_path_length" => 2, "oid_root_skip" => 2 },
          {"walk" => "foo", "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"tables" => [{"columns" => ["1.2.3.4", "4.3.2.1"]}], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
    ]

    context "validates get oids" do
      valid_configs.each_with_index do |config, index|
        context "with valid config #{index}" do
          let(:config) { config }
          it 'should not raise' do
            expect{ plugin.register }.not_to raise_error
          end
        end
      end

      invalid_configs.each_with_index do |config, index|
        context "with invalid config #{index}" do
          let(:config) { config }
          it 'should raise' do
            expect{ plugin.register }.to raise_error(LogStash::ConfigurationError)
          end
        end
      end
    end
  end

  context "hosts options validation" do
    valid_configs = [
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:localhost/161"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/112345"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "community" => "public"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "tcp:127.0.0.1/112345"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "tcp:127.0.0.1/161", "community" => "public"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "1"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "2c"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "3"}], "security_name" => "v3user"},

          {"get" => ["1.0"], "hosts" => [{"host" => "udp:[::1]/16100"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:[2001:db8:0:1:1:1:1:1]/16100"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:[2001:db8::2:1]/161"}]},
    ]

    invalid_configs = [
          {"get" => ["1.0"], "hosts" => [{"host" => "aaa:127.0.0.1/161"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "tcp.127.0.0.1/161"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "localhost"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "localhost/161"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/aaa"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161"}, {"host" => "udp:127.0.0.1/aaa"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "2"}]},
          {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "3a"}]},
          {"get" => ["1.0"], "hosts" => ""},
          {"get" => ["1.0"], "hosts" => []},
          {"get" => ["1.0"] },
    ]

    context "validates hosts" do
      valid_configs.each_with_index do |config, index|
        context "with valid config #{index}" do
          let(:config) { config }
          it 'should not raise' do
            expect{ plugin.register }.not_to raise_error
          end
        end
      end

      invalid_configs.each_with_index do |config, index|
        context "with invalid config #{index}" do
          let(:config) { config }
          it 'should raise' do
            expect{ plugin.register }.to raise_error(LogStash::ConfigurationError)
          end
        end
      end
    end
  end

  context "v3_users options validation" do
    valid_configs = [
	    {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "3"}], "security_name" => "ciscov3", "auth_protocol" => "sha", "auth_pass" => "myshapass", "priv_protocol" => "aes", "priv_pass" => "myprivpass", "security_level" => "authNoPriv"},
	    {"get" => ["1.0"], "hosts" => [{"host" => "udp:[2001:db8:0:1:1:1:1:1]/1610", "version" => "3"}], "security_name" => "dellv3", "auth_protocol" => "md5", "auth_pass" => "myshapass", "priv_protocol" => "3des", "priv_pass" => "myprivpass", "security_level" => "authNoPriv"}
    ]

    invalid_configs = [
	    {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "3"}], "security_name" => "ciscov3", "auth_protocol" => "badauth", "auth_pass" => "myshapass", "priv_protocol" => "aes", "priv_pass" => "myprivpass", "security_level" => "authNoPriv"},
	    {"get" => ["1.0"], "hosts" => [{"host" => "udp:127.0.0.1/161", "version" => "3"}], "security_name" => "ciscov3", "auth_protocol" => "sha"}
    ]

    context "validates v3_users" do
      valid_configs.each_with_index do |config, index|
        context "with valid config #{index}" do
          let(:config) { config }
          it 'should not raise' do
            expect{ plugin.register }.not_to raise_error
          end
        end
      end

      invalid_configs.each_with_index do |config, index|
        context "with invalid config #{index}" do
          let(:config) { config }
          it 'should raise' do
            expect{ plugin.register }.to raise_error(LogStash::ConfigurationError)
          end
        end
      end
    end
  end

  describe 'local_engine_id validation' do
    let(:local_engine_id) { nil }
    let(:config) { super().merge('get' => ["1.0"], 'hosts' => [{'host' => "udp:127.0.0.1/161", "version" => "2c"}], 'local_engine_id' => local_engine_id) }

    context 'with length lower than 5' do
      let(:local_engine_id) { '1234' }

      it 'should raise' do
        error_message = '`local_engine_id` length must be greater or equal than 5'
        expect { plugin.register }.to raise_error(LogStash::ConfigurationError, error_message)
      end
    end

    context 'with valid length' do
      let(:local_engine_id) { '0' * 32 }

      it 'should not raise' do
        expect { plugin.register }.to_not raise_error
      end
    end

    context 'with length greater than 32' do
      let(:local_engine_id) { '0' * 33 }

      it 'should raise' do
        error_message = '`local_engine_id` length must be lower or equal than 32'
        expect { plugin.register }.to raise_error(LogStash::ConfigurationError, error_message)
      end
    end
  end

  ecs_compatibility_matrix(:disabled, :v1, :v8) do |ecs_select|
    let(:queue) { Queue.new }
    let(:run_once_runner) { RunOnceStoppableIntervalRunner.new(plugin) }
    let(:config) {{'ecs_compatibility' => ecs_select.active_mode }}

    before(:each) do
      allow(plugin).to receive(:stoppable_interval_runner).and_return(run_once_runner)
      allow(plugin).to receive(:build_client!).and_return(mock_client)
      allow(mock_client).to receive(:listen)
      allow(mock_client).to receive(:create_target).and_return(mock_target)
      allow(mock_client).to receive(:close).at_most(:once)
    end

    context 'mocked get' do
      before(:each) do
        expect(mock_client).to receive(:get).and_return({"foo" => "bar"})
      end

      context 'should add' do
        let(:config) { super().merge({ 'get' => ["1.3.6.1.2.1.1.1.0"], 'hosts' => [{ 'host' => "udp:127.0.0.1/161", 'community' => "public" }] }) }

        it "@metadata and host fields to event" do
          plugin.register
          plugin.run(queue)
          event = queue.pop

          if ecs_select.active_mode == :disabled
            expect(event.get("[@metadata][host_protocol]")).to eq("udp")
            expect(event.get("[@metadata][host_address]")).to eq("127.0.0.1")
            expect(event.get("[@metadata][host_port]")).to eq("161")
            expect(event.get("[@metadata][host_community]")).to eq("public")
            expect(event.get("host")).to eql("127.0.0.1")
          else
            expect(event.get("[@metadata][input][snmp][host][protocol]")).to eq("udp")
            expect(event.get("[@metadata][input][snmp][host][address]")).to eq("127.0.0.1")
            expect(event.get("[@metadata][input][snmp][host][port]")).to eq('161')
            expect(event.get("[@metadata][input][snmp][host][community]")).to eq("public")
            expect(event.get("host")).to eql('ip' => "127.0.0.1")
          end
        end
      end

      context 'with custom host field (legacy metadata)' do
        let(:config) do
          super().merge({
            'get' => ["1.3.6.1.2.1.1.1.0"],
            'hosts' => [{ 'host' => "udp:127.0.0.1/161", 'community' => "public" }],
            'add_field' => { 'host' => '%{[@metadata][host_protocol]}:%{[@metadata][host_address]}/%{[@metadata][host_port]},%{[@metadata][host_community]}' }
          })
        end

        it "should add field to event" do
          plugin.register
          plugin.run(queue)
          event = queue.pop

          expect(event.get("host")).to eq("udp:127.0.0.1/161,public")
        end
      end if ecs_select.active_mode == :disabled

      context "with custom host field (ECS mode)" do
        let(:config) do
          super().merge({
            'get' => ["1.3.6.1.2.1.1.1.0"],
            'hosts' => [{ 'host' => "tcp:192.168.1.11/1161" }],
            'add_field' => { '[host][formatted]' => '%{[@metadata][input][snmp][host][protocol]}://%{[@metadata][input][snmp][host][address]}:%{[@metadata][input][snmp][host][port]}' }
          })
        end

        it "should add field to event" do
          plugin.register
          plugin.run(queue)
          event = queue.pop

          expect(event.get("host")).to eq('formatted' => "tcp://192.168.1.11:1161")
        end
      end if ecs_select.active_mode != :disabled

      context 'with target configured' do
        let(:config) do
          super().merge({
            'get' => ["1.3.6.1.2.1.1.1.0"],
            'hosts' => [{ 'host' => 'udp:127.0.0.1/161', 'community' => 'public' }],
            'target' => 'snmp_data'
          })
        end

        it 'should target event data' do
          plugin.register
          plugin.run(queue)
          event = queue.pop

          expect( event.include?('foo') ).to be false
          expect( event.get('[snmp_data]') ).to eql 'foo' => 'bar'
        end
      end
    end

    context 'mocked nil get response' do
      let(:config) do
        super().merge({
          'get' => ['1.3.6.1.2.1.1.1.0'],
          'hosts' => [{'host' => 'udp:127.0.0.1/161', 'community' => 'public'}]
        })
      end

      let(:logger) { double("Logger").as_null_object }

      before(:each) do
        expect(mock_client).to receive(:get).once.and_return(nil)
        allow(plugin).to receive(:logger).and_return(logger)
        expect(logger).not_to receive(:error)
      end

      it 'generates no events when client returns no response' do
        plugin.register
        plugin.poll_clients(queue)

        expect( queue.size ).to eql 0
      end
    end

    context 'mocked nil table response' do
      let(:config) do
        super().merge({
            'tables' => [
                { 'name' => "a1Table", 'columns' => ["1.3.6.1.4.1.3375.2.2.5.2.3.1.1"] }
            ],
            "hosts" => [{"host" => "udp:127.0.0.1/161", "community" => "public"}]
        })
      end

      let(:logger) { double("Logger").as_null_object }

      before do
        expect(mock_client).to receive(:table).once.and_return(nil)
        allow(plugin).to receive(:logger).and_return(logger)
        expect(logger).not_to receive(:error)
      end

      it 'generates no events when client returns no response' do
        plugin.register
        plugin.poll_clients(queue)

        expect( queue.size ).to eql 0
      end
    end

    context 'mocked nil walk response' do
      let(:config) do
        super().merge({
            'walk' => ["1.3.6.1.2.1.1"],
            "hosts" => [{"host" => "udp:127.0.0.1/161", "community" => "public"}]
        })
      end

      let(:logger) { double("Logger").as_null_object }

      before do
        expect(mock_client).to receive(:walk).once.and_return(nil)
        allow(plugin).to receive(:logger).and_return(logger)
        expect(logger).not_to receive(:error)
      end

      it 'generates no events when client returns no response' do
        plugin.register
        plugin.poll_clients(queue)

        expect( queue.size ).to eql 0
      end
    end
  end

  context "StoppableIntervalRunner" do
    let(:stop_holder) { Struct.new(:value).new(false) }

    before(:each) do
      allow(plugin).to receive(:stop?) { stop_holder.value }
    end

    let(:plugin) do
      double("Plugin").tap do |dbl|
        allow(dbl).to receive(:logger).and_return(double("Logger").as_null_object)
        allow(dbl).to receive(:stop?) { stop_holder.value }
      end
    end

    subject(:interval_runner) { LogStash::Inputs::Snmp::StoppableIntervalRunner.new(plugin) }

    context "#every" do
      context "when the plugin is stopped" do
        let(:interval_seconds) { 2 }
        it 'does not yield the block' do
          stop_holder.value = true
          expect { |yielder| interval_runner.every(interval_seconds, &yielder) }.to_not yield_control
        end
      end

      context "when the yield takes shorter than the interval" do
        let(:duration_seconds) { 1 }
        let(:interval_seconds) { 2 }

        it 'sleeps off the remainder' do
          allow(interval_runner).to receive(:sleep).and_call_original

          interval_runner.every(interval_seconds) do
            Kernel::sleep(duration_seconds) # non-stoppable
            stop_holder.value = true # prevent re-runs
          end

          expect(interval_runner).to have_received(:sleep).with(a_value_within(0.1).of(1))
        end
      end

      context "when the yield takes longer than the interval" do
        let(:duration_seconds) { 2 }
        let(:interval_seconds) { 1 }

        it 'logs a warning to the plugin' do
          allow(interval_runner).to receive(:sleep).and_call_original

          interval_runner.every(interval_seconds) do
            Kernel::sleep(duration_seconds) # non-stoppable
            stop_holder.value = true # prevent re-runs
          end

          expect(interval_runner).to_not have_received(:sleep)

          expect(plugin.logger).to have_received(:warn).with(a_string_including("took longer"), a_hash_including(:interval_seconds => interval_seconds, :duration_seconds => a_value_within(0.1).of(duration_seconds)))
        end
      end

      it 'runs regularly until the plugin is stopped' do
        timestamps = []

        thread = Thread.new do
          interval_runner.every(1) do
            timestamps << Time.now
            Kernel::sleep(Random::rand(0.8))
          end
        end

        Kernel::sleep(5)
        expect(thread).to be_alive

        stop_holder.value = true
        Kernel::sleep(1)

        aggregate_failures do
          expect(thread).to_not be_alive
          expect(timestamps.count).to be_within(1).of(5)

          timestamps.each_cons(2) do |previous, current|
            # ensure each start time is very close to 1s after the previous.
            expect(current - previous).to be_within(0.05).of(1)
          end

          thread.kill if thread.alive?
        end
      end
    end
  end

  context "close" do
    let(:config) do
      {
        'get' => ["1.3.6.1.2.1.1.1.0"],
        'hosts' => [{'host' => "udp:127.0.0.1/161", 'community' => "public"}]
      }
    end

    let(:run_once_runner) { RunOnceStoppableIntervalRunner.new(plugin) }

    before(:each) do
      allow(plugin).to receive(:stoppable_interval_runner).and_return(run_once_runner)
      allow(plugin).to receive(:build_client!).and_return(mock_client)
      allow(mock_client).to receive(:listen)
      allow(mock_client).to receive(:create_target).and_return(mock_target)
      allow(mock_client).to receive(:get).and_return({"foo" => "bar"})
      allow(mock_client).to receive(:close)
    end

    it "should call client close method upon termination" do
      plugin.register
      plugin.run(Queue.new)
      plugin.do_close

      expect(mock_client).to have_received(:close).once
    end
  end
end

class RunOnceStoppableIntervalRunner
  def initialize(plugin)
    @plugin = plugin
  end

  def every(interval_seconds, desc="operation", &block)
    yield
  end
end

