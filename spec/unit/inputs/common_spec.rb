require 'logstash/devutils/rspec/spec_helper'
require 'digest'
require_relative '../../../lib/logstash/inputs/snmp'
require_relative '../../../lib/logstash/inputs/snmptrap'

shared_examples 'a common SNMP plugin' do
  let(:mock_client) { double('org.logstash.snmp.SnmpClient') }

  context 'oid_root_skip and oid_path_length validation' do
    before(:each) do
      allow(plugin).to receive(:build_client!).and_return(mock_client)
    end

    context 'with only `oid_root_skip` set' do
      let(:config) { super().merge('oid_mapping_format' => 'default', 'oid_root_skip' => 1) }
      it 'should not raise' do
        expect { plugin.register }.to_not raise_error
      end
    end

    context 'with only `oid_path_length` set' do
      let(:config) { super().merge('oid_mapping_format' => 'default', 'oid_path_length' => 1) }
      it 'should not raise' do
        expect { plugin.register }.to_not raise_error
      end
    end

    context 'with `oid_root_skip` and `oid_path_length` set' do
      let(:config) { super().merge({ 'oid_mapping_format' => 'default', 'oid_root_skip' => 1, 'oid_path_length' => 1 }) }
      it 'should raise' do
        expect { plugin.register }.to raise_error(LogStash::ConfigurationError, 'Use either `oid_root_skip` or `oid_path_length`')
      end
    end
  end

  context 'oid_mapping_format validation' do
    before(:each) do
      allow(plugin).to receive(:build_client!).and_return(mock_client)
    end

    context 'with value set to `default`' do
      let(:config) { super().merge('oid_mapping_format' => 'default') }
      context 'and oid_root_skip set' do
        let(:config) { super().merge('oid_root_skip' => 1) }
        it 'should not raise' do
          expect { plugin.register }.to_not raise_error
        end
      end

      context 'and oid_path_length set' do
        let(:config) { super().merge('oid_path_length' => 1) }
        it 'should not raise' do
          expect { plugin.register }.to_not raise_error
        end
      end
    end

    %w[ruby_snmp dotted_string].each do |format|
      context "with value set to `#{format}`" do
        let(:config) { super().merge('oid_mapping_format' => format) }

        context 'and oid_root_skip set' do
          let(:config) { super().merge('oid_root_skip' => 1) }
          it 'should raise' do
            expect { plugin.register }.to raise_error(LogStash::ConfigurationError, 'The `oid_root_skip` and `oid_path_length` requires setting `oid_mapping_format` to `default`')
          end
        end

        context 'and oid_path_length set' do
          let(:config) { super().merge('oid_path_length' => 1) }
          it 'should raise' do
            expect { plugin.register }.to raise_error(LogStash::ConfigurationError, 'The `oid_root_skip` and `oid_path_length` requires setting `oid_mapping_format` to `default`')
          end
        end
      end
    end

    context 'build_mib_manager!' do
      context 'with mib_paths set' do
        let(:config) { super().merge('mib_paths' => %w[/foo /bar]) }
        let(:mock_mib_manager) { double('org.logstash.snmp.mib.MibManager') }

        it 'should add paths to MIB manager' do
          allow(plugin).to receive(:new_mib_manager).and_return(mock_mib_manager)
          allow(mock_mib_manager).to receive(:add)

          mib_manager = plugin.build_mib_manager!

          expect(mib_manager).to have_received(:add).with('/foo')
          expect(mib_manager).to have_received(:add).with('/bar')
        end
      end

      context 'with `use_provided_mibs` set to `true`' do
        let(:config) { super().merge('use_provided_mibs' => true) }
        let(:mock_mib_manager) { double('org.logstash.snmp.mib.MibManager') }

        it 'should add provided paths to MIB manager' do
          allow(plugin).to receive(:new_mib_manager).and_return(mock_mib_manager)
          allow(mock_mib_manager).to receive(:add)

          mib_manager = plugin.build_mib_manager!

          LogStash::PluginMixins::Snmp::Common::MIB_PROVIDED_PATHS.each do |path|
            expect(mib_manager).to have_received(:add).with(path)
          end
        end
      end

      context 'with `use_provided_mibs` set to `false`' do
        let(:config) { super().merge('use_provided_mibs' => false) }
        let(:mock_mib_manager) { double('org.logstash.snmp.mib.MibManager') }

        it 'should not add provided paths to MIB manager' do
          allow(plugin).to receive(:new_mib_manager).and_return(mock_mib_manager)
          allow(mock_mib_manager).to receive(:add)

          mib_manager = plugin.build_mib_manager!

          expect(mib_manager).to_not have_received(:add)
        end
      end

      { 'default' => org.logstash.snmp.DefaultOidFieldMapper,
        'ruby_snmp' => org.logstash.snmp.RubySnmpOidFieldMapper,
        'dotted_string' => org.logstash.snmp.DottedStringOidFieldMapper }.each do |format, expected_kind|
        context "with `oid_mapping_format` set to `#{format}`" do
          let(:config) { super().merge('oid_mapping_format' => format) }

          it "should use `#{expected_kind}` field mapper" do
            mib_manager = plugin.build_mib_manager!
            expect(mib_manager.getFieldMapper).to be_a expected_kind
          end
        end
      end
    end
  end

  context '#build_snmp_client!' do
    let(:client_builder) { double('org.logstash.snmp.SnmpClientBuilder') }

    before(:each) do
      allow(client_builder).to receive(:setEngineBootsPersistencePath)
    end

    it 'sets the engine boots persistence path' do
      allow(plugin).to receive(:engine_boots_state_file_path).and_return('/tmp/snmp.engineboots')

      expect(client_builder).to receive(:setEngineBootsPersistencePath).with('/tmp/snmp.engineboots')
      expect(client_builder).to receive(:setMapOidVariableValues)
      expect(client_builder).to receive(:build)

      plugin.build_snmp_client!(client_builder)
    end

    context 'with `local_engine_id` set' do
      let(:config) { super().merge('local_engine_id' => '0123456789') }

      it 'sets the client local engine id' do
        expect(client_builder).to receive(:setLocalEngineId).with('0123456789')
        expect(client_builder).to receive(:setMapOidVariableValues)
        expect(client_builder).to receive(:build)

        plugin.build_snmp_client!(client_builder)
      end
    end

    context 'with `local_engine_id` set as a hexadecimal string' do
      let(:config) { super().merge('local_engine_id' => '0x80001f88806763084db5aebf6600000000') }

      it 'sets the client local engine id using decoded bytes' do
        expected_engine_id = ['80001f88806763084db5aebf6600000000'].pack('H*').to_java_bytes

        expect(client_builder).to receive(:setLocalEngineId).with(expected_engine_id)
        expect(client_builder).to receive(:setMapOidVariableValues)
        expect(client_builder).to receive(:build)

        plugin.build_snmp_client!(client_builder)
      end

      it 'raises a clear configuration error when the reflective fallback cannot find the engine id field' do
        java_class = double('java_class', :declared_fields => [])
        reflective_builder = double('reflective_builder', :java_class => java_class)

        expect do
          plugin.send(:set_local_engine_id_bytes_with_reflection!, reflective_builder, ['80001f88806763084db5aebf6600000000'].pack('H*').to_java_bytes)
        end.to raise_error(
          LogStash::ConfigurationError,
          'Unable to set `local_engine_id`: SNMP client builder does not expose the `localEngineId` field for the reflective fallback'
        )
      end
    end

    context 'with USM user validation' do
      let(:config) { super().merge('security_name' => 'public') }

      context 'with `security_name` not set' do
        let(:config) { super().reject! { |k| k == 'security_name'} }

        it 'should raise' do
          error_message = '`security_name` is required when SNMP v3 is enabled'
          expect { plugin.build_snmp_client!(client_builder, validate_usm_user: true) }.to raise_error(LogStash::ConfigurationError, error_message)
        end
      end

      context 'with `security_level` set to `noAuthNoPriv`' do
        let(:config) do
          {
            'security_name' => 'foobar',
            'security_level' => 'noAuthNoPriv'
          }
        end

        it 'should not raise' do
          expect(client_builder).to receive(:addUsmUser)
          expect(client_builder).to receive(:setMapOidVariableValues)
          expect(client_builder).to receive(:build)
          expect { plugin.build_snmp_client!(client_builder, validate_usm_user: true) }.to_not raise_error
        end
      end

      [{ protocol: 'auth_protocol', pass: 'auth_pass', protocol_value: 'md5', security_levels: %w[authPriv authNoPriv]},
       { protocol: 'priv_protocol', pass: 'priv_pass', protocol_value: 'des', security_levels: %w[authPriv] }].each do |config|
        context "with only `#{config[:protocol]}` set" do
          let(:config) { super().merge((config[:protocol]).to_s => (config[:protocol_value]).to_s ) }

          it 'should raise' do
            error_message = /Using `#{config[:protocol]}` requires the `#{config[:pass]}`/
            expect { plugin.build_snmp_client!(client_builder, validate_usm_user: true) }.to raise_error(LogStash::ConfigurationError, error_message)
          end
        end

        context "with only `#{config[:pass]}` set" do
          let(:config) { super().merge((config[:pass]).to_s => 'foobar') }

          it 'should raise' do
            error_message = /`#{config[:protocol]}` is required when using `#{config[:pass]}`/
            expect { plugin.build_snmp_client!(client_builder, validate_usm_user: true) }.to raise_error(LogStash::ConfigurationError, error_message)
          end
        end

        context "with both `#{config[:protocol]}` and `#{config[:pass]}` set" do
          let(:config) { super().merge({ "#{config[:protocol]}" => config[:protocol_value], "#{config[:pass]}" => '*' * 10 }) }

          it 'should not raise' do
            expect(client_builder).to receive(:addUsmUser)
            expect(client_builder).to receive(:setMapOidVariableValues)
            expect(client_builder).to receive(:build)
            expect { plugin.build_snmp_client!(client_builder, validate_usm_user: true) }.to_not raise_error
          end
        end

        context "with valid `#{config[:pass]}` length" do
          let(:config) { super().merge({ "#{config[:protocol]}" => config[:protocol_value], "#{config[:pass]}" => '*' * 8 }) }

          it 'should not raise' do
            expect(client_builder).to receive(:addUsmUser)
            expect(client_builder).to receive(:setMapOidVariableValues)
            expect(client_builder).to receive(:build)
            expect { plugin.build_snmp_client!(client_builder, validate_usm_user: true) }.to_not raise_error
          end
        end

        context "with invalid `#{config[:pass]}` length" do
          let(:config) { super().merge("#{config[:pass]}" => '**') }

          it 'should raise' do
            error_message = /`#{config[:pass]}` passphrase must be at least 8 bytes long/
            expect { plugin.build_snmp_client!(client_builder, validate_usm_user: true) }.to raise_error(LogStash::ConfigurationError, error_message)
          end
        end

        config[:security_levels].each do |security_level|
          context "with `security_level` set to `#{security_level}`" do
            let(:config) { super().merge('security_level' => security_level) }

            context "and no `#{config[:protocol]}` set" do
              let(:config) { super().reject { |k| k == config[:protocol] } }

              it 'should raise' do
                error_message = /Using `security_level` set to `#{security_level}` requires the configuration of `#{config[:protocol]}`/
                expect { plugin.build_snmp_client!(client_builder, validate_usm_user: true) }.to raise_error(LogStash::ConfigurationError, error_message)
              end
            end
          end
        end
      end
    end
  end

  describe '#engine_boots_state_file_path' do
    before(:each) do
      allow(plugin).to receive(:logstash_data_path).and_return('/tmp/logstash-data')
    end

    it 'extracts the pipeline id when available' do
      allow(plugin).to receive(:execution_context).and_return(double('context', :pipeline => double('pipeline', :pipeline_id => 'main')))

      expect(plugin.send(:pipeline_state_key)).to eq('main')
    end

    it 'uses the helper state keys when building the path' do
      allow(plugin).to receive(:pipeline_state_key).and_return('main')
      allow(plugin).to receive(:explicit_plugin_id_state_key).and_return('trap-a')
      allow(plugin).to receive(:single_plugin_instance_in_pipeline?).and_return(false)
      allow(Digest::SHA256).to receive(:hexdigest).and_return('state-key-digest')

      expected_state_key = [
        plugin.class.config_name,
        'main',
        'trap-a',
        plugin.instance_variable_get(:@host),
        plugin.instance_variable_get(:@port),
        plugin.send(:normalized_hosts_state_key)
      ].compact.join('|')

      expect(plugin.send(:engine_boots_state_file_path)).to eq('/tmp/logstash-data/plugins/inputs/snmp/state-key-digest.engineboots')
      expect(Digest::SHA256).to have_received(:hexdigest).with(expected_state_key)
    end

    it 'uses only the plugin type and pipeline id when there is a single plugin instance in the pipeline' do
      allow(plugin).to receive(:pipeline_state_key).and_return('jsa-snmp-input-filter')
      allow(plugin).to receive(:single_plugin_instance_in_pipeline?).and_return(true)
      allow(Digest::SHA256).to receive(:hexdigest).and_return('state-key-digest')

      expect(plugin.send(:engine_boots_state_file_path)).to eq('/tmp/logstash-data/plugins/inputs/snmp/state-key-digest.engineboots')
      expect(Digest::SHA256).to have_received(:hexdigest).with("#{plugin.class.config_name}|jsa-snmp-input-filter")
    end

    it 'includes the explicit plugin id when configured' do
      plugin_with_id = described_class.new(config.merge('id' => 'trap-a'))
      expect(plugin_with_id.send(:explicit_plugin_id_state_key)).to eq('trap-a')
    end

    it 'does not include an auto-generated plugin id when it was not configured' do
      expect(plugin.send(:explicit_plugin_id_state_key)).to be_nil
    end

    it 'detects a single plugin instance from the pipeline execution context' do
      pipeline = double('pipeline', :inputs => [plugin])
      allow(plugin).to receive(:execution_context).and_return(double('context', :pipeline => pipeline))

      expect(plugin.send(:single_plugin_instance_in_pipeline?)).to be(true)
    end
  end

  describe 'local_engine_id validation' do
    let(:local_engine_id) { nil }
    let(:config) { super().merge('local_engine_id' => local_engine_id) }

    before(:each) do
      allow(plugin).to receive(:build_client!).and_return(mock_client)
    end

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

    context 'with valid hexadecimal length' do
      let(:local_engine_id) { '0x80001f88806763084db5aebf6600000000' }

      it 'should not raise' do
        expect { plugin.register }.to_not raise_error
      end
    end

    context 'with invalid hexadecimal content' do
      let(:local_engine_id) { '0x80001f88806763084db5aebf66000000ZZ' }

      it 'should raise' do
        error_message = '`local_engine_id` must be a valid hexadecimal string when using the `0x` prefix'
        expect { plugin.register }.to raise_error(LogStash::ConfigurationError, error_message)
      end
    end

    context 'with an odd number of hexadecimal digits' do
      let(:local_engine_id) { '0x12345' }

      it 'should raise' do
        error_message = '`local_engine_id` must contain an even number of hexadecimal digits when using the `0x` prefix'
        expect { plugin.register }.to raise_error(LogStash::ConfigurationError, error_message)
      end
    end

    context 'with hexadecimal content shorter than 5 bytes' do
      let(:local_engine_id) { '0x01020304' }

      it 'should raise' do
        error_message = '`local_engine_id` length must be greater or equal than 5'
        expect { plugin.register }.to raise_error(LogStash::ConfigurationError, error_message)
      end
    end

    context 'with length greater than 32' do
      let(:local_engine_id) { '0' * 33 }

      it 'should raise' do
        error_message = '`local_engine_id` length must be lower or equal than 32'
        expect { plugin.register }.to raise_error(LogStash::ConfigurationError, error_message)
      end
    end

    context 'with hexadecimal content greater than 32 bytes' do
      let(:local_engine_id) { '0x' + ('ab' * 33) }

      it 'should raise' do
        error_message = '`local_engine_id` length must be lower or equal than 32'
        expect { plugin.register }.to raise_error(LogStash::ConfigurationError, error_message)
      end
    end
  end

  it 'should default `use_provided_mibs` to `true`' do
    expect(plugin.config['use_provided_mibs']).to eql(true)
  end

  it 'should default `oid_mapping_format` to `default`' do
    expect(plugin.config['oid_mapping_format']).to eql('default')
  end

  it 'should default `oid_map_field_values` to `false`' do
    expect(plugin.config['oid_map_field_values']).to  eql(false)
  end
end

describe 'SNMP input plugins' do
  let(:config) { {} }
  subject(:plugin) { described_class.new(config) }

  describe LogStash::Inputs::Snmp do
    let(:config) { { 'get' => ['1.3.6.1.2.1.1.1.0'], 'hosts' => [{'host' => 'udp:127.0.0.1/161'}] } }

    it_behaves_like 'a common SNMP plugin'
  end

  describe LogStash::Inputs::Snmptrap do
    it_behaves_like 'a common SNMP plugin'
  end
end
