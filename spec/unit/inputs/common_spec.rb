require "logstash/devutils/rspec/spec_helper"
require_relative '../../../lib/logstash/inputs/snmp'
require_relative '../../../lib/logstash/inputs/snmptrap'

shared_examples "a common SNMP plugin" do
  let(:mock_client) { double("org.logstash.snmp.SnmpClient") }

  context 'oid_root_skip and oid_path_length validation' do
    before(:each) do
      allow(plugin).to receive(:build_client!).and_return(mock_client)
    end

    context "with only `oid_root_skip` set" do
      let(:config) { super().merge('oid_mapping_format' => 'default', 'oid_root_skip' => 1) }
      it 'should not raise' do
        expect{ plugin.register }.to_not raise_error
      end
    end

    context "with only `oid_path_length` set" do
      let(:config) { super().merge('oid_mapping_format' => 'default', 'oid_path_length' => 1) }
      it 'should not raise' do
        expect{ plugin.register }.to_not raise_error
      end
    end

    context "with `oid_root_skip` and `oid_path_length` set" do
      let(:config) { super().merge({'oid_mapping_format' => 'default', 'oid_root_skip' => 1, 'oid_path_length' => 1}) }
      it 'should raise' do
        expect{ plugin.register }.to raise_error(LogStash::ConfigurationError, 'Use either `oid_root_skip` or `oid_path_length`')
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
        let(:config) { super().merge("oid_root_skip" => 1 ) }
        it 'should not raise' do
          expect{ plugin.register }.to_not raise_error
        end
      end

      context 'and oid_path_length set' do
        let(:config) { super().merge("oid_path_length" => 1 ) }
        it 'should not raise' do
          expect{ plugin.register }.to_not raise_error
        end
      end
    end

    %w[ruby_snmp dotted_string].each do |format|
      context "with value set to `#{format}`" do
        let(:config) { super().merge('oid_mapping_format' => format) }

        context 'and oid_root_skip set' do
          let(:config) { super().merge("oid_root_skip" => 1 ) }
          it 'should raise' do
            expect{ plugin.register }.to raise_error(LogStash::ConfigurationError, 'The `oid_root_skip` and `oid_path_length` requires setting `oid_mapping_format` to `default`')
          end
        end

        context 'and oid_path_length set' do
          let(:config) { super().merge("oid_path_length" => 1 ) }
          it 'should raise' do
            expect{ plugin.register }.to raise_error(LogStash::ConfigurationError, 'The `oid_root_skip` and `oid_path_length` requires setting `oid_mapping_format` to `default`')
          end
        end
      end
    end

    context 'build_mib_manager!' do
      context 'with mib_paths set' do
        let(:config) { super().merge('mib_paths' => %w[/foo /bar]) }
        let(:mock_mib_manager) { double("org.logstash.snmp.mib.MibManager") }

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
        let(:mock_mib_manager) { double("org.logstash.snmp.mib.MibManager") }

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
        let(:mock_mib_manager) { double("org.logstash.snmp.mib.MibManager") }

        it 'should not add provided paths to MIB manager' do
          allow(plugin).to receive(:new_mib_manager).and_return(mock_mib_manager)
          allow(mock_mib_manager).to receive(:add)

          mib_manager = plugin.build_mib_manager!

          expect(mib_manager).to_not have_received(:add)
        end
      end

      { 'default' => org.logstash.snmp.DefaultOidFieldMapper,
        'ruby_snmp' => org.logstash.snmp.RubySnmpOidFieldMapper,
        'dotted_string' => org.logstash.snmp.DottedStringOidFieldMapper, }.each do |format, expected_kind|
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
end

describe 'SNMP input plugins' do
  let(:config) {{}}
  subject(:plugin) { described_class.new(config) }

  describe LogStash::Inputs::Snmp do
    let(:config) {{ 'get' => ['1.3.6.1.2.1.1.1.0'], 'hosts' => [{'host' => 'udp:127.0.0.1/161'}] }}

    it_behaves_like 'a common SNMP plugin'

    it 'should default `use_provided_mibs` to `true`' do
      expect(plugin.config['use_provided_mibs']).to eql(true)
    end

    it 'should default `oid_mapping_format` to `default`' do
      expect(plugin.config['oid_mapping_format']).to eql('default')
    end

    it 'should default `oid_map_field_values` to `false`' do
      expect(plugin.config['oid_map_field_values']).to eql(false)
    end
  end

  describe LogStash::Inputs::Snmptrap do
    it_behaves_like 'a common SNMP plugin'

    it 'should default `use_provided_mibs` to `false`' do
      expect(plugin.config['use_provided_mibs']).to eql(false)
    end

    it 'should default `oid_mapping_format` to `ruby_snmp`' do
      expect(plugin.config['oid_mapping_format']).to eql('ruby_snmp')
    end

    it 'should default `oid_map_field_values` to `true`' do
      expect(plugin.config['oid_map_field_values']).to  eql(true)
    end
  end
end
