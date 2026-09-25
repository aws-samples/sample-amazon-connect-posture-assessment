"""
Extended CLI coverage — tests for helper functions and config operations.
"""

import pytest

from amazon_connect_assessment.cli import (
    ConfigurationManager,
    create_argument_parser,
    merge_cli_args_with_config,
    setup_logging_from_args,
)


class TestConfigurationManagerExtended:
    def test_env_override_region(self, monkeypatch):
        monkeypatch.setenv("AWS_REGION", "eu-west-1")
        mgr = ConfigurationManager()
        config = mgr.load_config()
        assert config["aws"]["region"] == "eu-west-1"

    def test_env_override_log_level(self, monkeypatch):
        monkeypatch.setenv("CONNECT_ASSESSMENT_LOG_LEVEL", "DEBUG")
        mgr = ConfigurationManager()
        config = mgr.load_config()
        assert config["global_settings"]["log_level"] == "DEBUG"

    def test_env_override_timeout(self, monkeypatch):
        monkeypatch.setenv("CONNECT_ASSESSMENT_TIMEOUT", "600")
        mgr = ConfigurationManager()
        config = mgr.load_config()
        assert config["global_settings"]["timeout"] == 600

    def test_validate_invalid_timeout(self):
        mgr = ConfigurationManager()
        mgr.load_config()
        mgr.config["global_settings"]["timeout"] = -1
        errors = mgr.validate_config()
        assert any("timeout" in e for e in errors)

    def test_validate_invalid_output_format(self):
        mgr = ConfigurationManager()
        mgr.load_config()
        mgr.config["output"]["format"] = ["pdf"]
        errors = mgr.validate_config()
        assert any("pdf" in e for e in errors)

    def test_validate_invalid_severity(self):
        mgr = ConfigurationManager()
        mgr.load_config()
        mgr.config["enabled_severities"] = ["extreme"]
        errors = mgr.validate_config()
        assert any("extreme" in e for e in errors)

    def test_get_config_returns_copy(self):
        mgr = ConfigurationManager()
        mgr.load_config()
        c1 = mgr.get_config()
        c1["new_key"] = "x"
        assert "new_key" not in mgr.config


class TestMergeCliArgs:
    def test_region_override(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--region", "ap-southeast-1"])
        config = ConfigurationManager().load_config()
        merged = merge_cli_args_with_config(args, config)
        assert merged["aws"]["region"] == "ap-southeast-1"

    def test_sequential_flag(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--sequential"])
        config = ConfigurationManager().load_config()
        merged = merge_cli_args_with_config(args, config)
        assert merged["global_settings"]["parallel_execution"] is False

    def test_output_format_override(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--output-format", "json", "csv"])
        config = ConfigurationManager().load_config()
        merged = merge_cli_args_with_config(args, config)
        assert merged["output"]["format"] == ["json", "csv"]

    def test_config_output_format_survives_without_cli_override(self):
        parser = create_argument_parser()
        args = parser.parse_args([])
        config = ConfigurationManager().load_config()
        config["output"]["format"] = ["json", "csv"]
        merged = merge_cli_args_with_config(args, config)
        assert merged["output"]["format"] == ["json", "csv"]

    def test_output_format_defaults_to_none_for_config_precedence(self):
        parser = create_argument_parser()
        args = parser.parse_args([])
        assert args.output_format is None

    def test_output_directory_cli_override(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--output-dir", "/tmp/custom-reports"])
        config = ConfigurationManager().load_config()
        config["output"]["directory"] = "/var/reports"
        merged = merge_cli_args_with_config(args, config)
        assert merged["output"]["directory"] == "/tmp/custom-reports"

    def test_config_output_directory_survives_without_cli_override(self):
        parser = create_argument_parser()
        args = parser.parse_args([])
        config = ConfigurationManager().load_config()
        config["output"]["directory"] = "/var/reports"
        merged = merge_cli_args_with_config(args, config)
        assert merged["output"]["directory"] == "/var/reports"

    def test_max_workers_override(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--max-workers", "16"])
        config = ConfigurationManager().load_config()
        merged = merge_cli_args_with_config(args, config)
        assert merged["global_settings"]["max_workers"] == 16

    def test_explicit_zero_numeric_values_are_preserved(self):
        # Zero is valid for these, so the merge must not drop it as falsy.
        parser = create_argument_parser()
        args = parser.parse_args(["--retry-base-delay", "0", "--retry-max-delay", "0"])
        config = ConfigurationManager().load_config()

        merged = merge_cli_args_with_config(args, config)

        assert merged["global_settings"]["retry_base_delay"] == 0
        assert merged["global_settings"]["retry_max_delay"] == 0

    @pytest.mark.parametrize(
        "flag", ["--timeout", "--max-retry-attempts", "--max-workers", "--batch-size"]
    )
    def test_zero_is_rejected_where_a_positive_value_is_required(self, flag, capsys):
        with pytest.raises(SystemExit) as exc:
            create_argument_parser().parse_args([flag, "0"])
        assert exc.value.code == 2
        assert "must be a positive integer" in capsys.readouterr().err


class TestSetupLogging:
    def test_quiet_sets_error(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--quiet"])
        config = {"global_settings": {"log_level": "INFO"}}
        # Should not raise.
        setup_logging_from_args(args, config)

    def test_verbose_sets_info(self):
        parser = create_argument_parser()
        args = parser.parse_args(["-v"])
        config = {"global_settings": {"log_level": "WARNING"}}
        setup_logging_from_args(args, config)

    def test_double_verbose_sets_debug(self):
        parser = create_argument_parser()
        args = parser.parse_args(["-vv"])
        config = {"global_settings": {"log_level": "WARNING"}}
        setup_logging_from_args(args, config)


class TestBlankConfigValues:
    """Empty YAML keys load as None; validation must not crash on them."""

    @pytest.mark.parametrize(
        "yaml_text",
        [
            "enabled_pillars:\n",
            "enabled_severities:\n",
            "global_settings:\n  log_level:\n",
            "output:\n  format:\n",
            "output:\n",
        ],
    )
    def test_blank_values_validate_cleanly(self, tmp_path, yaml_text):
        path = tmp_path / "cfg.yaml"
        path.write_text(yaml_text)
        mgr = ConfigurationManager()
        config = mgr.load_config(str(path))
        assert mgr.validate_config(config) == []

    def test_blank_section_keeps_defaults(self, tmp_path):
        path = tmp_path / "cfg.yaml"
        path.write_text("output:\n")
        config = ConfigurationManager().load_config(str(path))
        assert config["output"]["format"]


class TestMainValidation:
    def test_filename_template_attribute_access_is_reported(self, monkeypatch, capsys):
        from amazon_connect_assessment import cli

        monkeypatch.setattr(
            "sys.argv", ["prog", "--output-filename", "{timestamp.x}", "--validate-config"]
        )
        assert cli.main() == 1
        assert "Filename template" in capsys.readouterr().out

    def test_show_config_prints_even_when_invalid(self, tmp_path, monkeypatch, capsys):
        from amazon_connect_assessment import cli

        path = tmp_path / "cfg.yaml"
        path.write_text("enabled_pillars: [bogus]\n")
        monkeypatch.setattr("sys.argv", ["prog", "--config", str(path), "--show-config"])
        assert cli.main() == 1
        out = capsys.readouterr().out
        assert "bogus" in out
        assert "Configuration validation failed" in out
