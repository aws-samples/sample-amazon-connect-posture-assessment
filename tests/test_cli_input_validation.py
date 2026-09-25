"""
CLI inputs are validated before the assessment runs, so a bad value fails fast
instead of crashing mid-run or after reports are written.
"""

import json
import sys
from unittest.mock import Mock, patch

import pytest

from amazon_connect_assessment import cli
from amazon_connect_assessment.cli import (
    ConfigurationManager,
    create_argument_parser,
    merge_cli_args_with_config,
    validate_run_inputs,
)


def _merged(*argv):
    args = create_argument_parser().parse_args(list(argv))
    return merge_cli_args_with_config(args, ConfigurationManager().load_config())


class TestArgumentTypes:
    @pytest.mark.parametrize(
        "argv",
        [
            ["--quiet", "-v"],
            ["--parallel", "--sequential"],
            ["--retry-count", "2"],
            ["--retry-base-delay", "-0.5"],
            ["--retry-max-delay", "inf"],
            ["--max-workers", "two"],
        ],
    )
    def test_rejected_at_parse_time(self, argv):
        with pytest.raises(SystemExit) as exc:
            create_argument_parser().parse_args(argv)
        assert exc.value.code == 2


class TestMergedConfigValidation:
    def test_config_file_values_are_validated_after_merge(self):
        manager = ConfigurationManager()
        config = manager.load_config()
        config["global_settings"]["batch_size"] = 0

        assert any("batch_size" in e for e in manager.validate_config(config))

    def test_defaults_are_valid(self):
        assert validate_run_inputs(_merged()) == []


class TestValidateRunInputs:
    def test_unknown_check_ids_are_listed(self):
        errors = validate_run_inputs(_merged("--checks", "nope-001", "security-iam-001"))

        assert len(errors) == 1
        assert "nope-001" in errors[0] and "security-iam-001" not in errors[0]
        assert "--list-checks" in errors[0]

    def test_unknown_exclude_check_ids_are_listed(self):
        (error,) = validate_run_inputs(_merged("--exclude-checks", "nope-001"))

        assert error.startswith("--exclude-checks")

    def test_known_check_ids_pass(self):
        assert validate_run_inputs(_merged("--checks", "security-iam-001")) == []

    @pytest.mark.parametrize(
        "template, message",
        [
            ("../x", "not a path"),
            ("report_{foo}", "unknown placeholder"),
            ("report_{0}", "unknown placeholder"),
        ],
    )
    def test_bad_filename_template(self, template, message):
        (error,) = validate_run_inputs(_merged("--output-filename", template))

        assert message in error

    def test_filename_template_with_all_placeholders_passes(self):
        template = "r_{timestamp}_{account_id}_{region}_{assessment_id}"

        assert validate_run_inputs(_merged("--output-filename", template)) == []

    def test_invalid_s3_bucket(self):
        (error,) = validate_run_inputs(_merged("--s3-output", "--s3-bucket", "Bad_Bucket"))

        assert "not a valid S3 bucket name" in error

    def test_missing_diff_baseline(self, tmp_path):
        (error,) = validate_run_inputs(_merged("--diff", str(tmp_path / "missing.json")))

        assert "not found" in error

    def test_diff_baseline_must_be_a_report(self, tmp_path):
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{not json")
        not_report = tmp_path / "other.json"
        not_report.write_text(json.dumps({"hello": 1}))

        assert "not valid JSON" in validate_run_inputs(_merged("--diff", str(bad_json)))[0]
        assert "no 'findings'" in validate_run_inputs(_merged("--diff", str(not_report)))[0]

    def test_valid_diff_baseline_passes(self, tmp_path):
        report = tmp_path / "report.json"
        report.write_text(json.dumps({"findings": []}))

        assert validate_run_inputs(_merged("--diff", str(report))) == []

    def test_log_file_directory_must_exist(self, tmp_path):
        errors = validate_run_inputs(_merged(), log_file=str(tmp_path / "nope" / "run.log"))

        assert "does not exist" in errors[0]

    def test_log_file_cannot_be_a_directory(self, tmp_path):
        errors = validate_run_inputs(_merged(), log_file=str(tmp_path))

        assert "is a directory" in errors[0]

    def test_output_dir_that_is_a_file(self, tmp_path):
        a_file = tmp_path / "reports"
        a_file.write_text("")

        (error,) = validate_run_inputs(_merged("--output-dir", str(a_file)))

        assert "not a directory" in error

    def test_output_dir_under_a_file_is_rejected(self, tmp_path):
        a_file = tmp_path / "file"
        a_file.write_text("")

        (error,) = validate_run_inputs(_merged("--output-dir", str(a_file / "reports")))

        assert "cannot be created" in error and str(a_file) in error

    def test_output_dir_parent_must_be_writable(self, tmp_path):
        locked = tmp_path / "locked"
        locked.mkdir()
        with patch.object(cli.os, "access", return_value=False):
            (error,) = validate_run_inputs(_merged("--output-dir", str(locked / "a" / "b")))

        assert "not writable" in error and str(locked) in error

    def test_new_output_dir_under_writable_parent_passes(self, tmp_path):
        assert validate_run_inputs(_merged("--output-dir", str(tmp_path / "a" / "b"))) == []

    @pytest.mark.parametrize(
        "argv",
        [
            ["--pillars", "resilience", "--checks", "security-iam-001"],
            ["--checks", "security-iam-001", "--exclude-checks", "security-iam-001"],
        ],
    )
    def test_filters_that_leave_no_checks_are_rejected(self, argv):
        (error,) = validate_run_inputs(_merged(*argv))

        assert "No checks remain" in error

    def test_checks_disabled_in_config_count_toward_empty_selection(self):
        config = _merged("--checks", "security-iam-001")
        config["checks"] = {"security-iam-001": {"enabled": False}}

        (error,) = validate_run_inputs(config)

        assert "No checks remain" in error

    def test_compatible_filters_pass(self):
        assert (
            validate_run_inputs(_merged("--pillars", "security", "--checks", "security-iam-001"))
            == []
        )


class TestMainFailsFast:
    def _run_main(self, monkeypatch, *argv):
        monkeypatch.setattr(sys, "argv", ["amazon-connect-assessment", *argv])
        return cli.main()

    def test_invalid_input_exits_before_aws_setup(self, monkeypatch, capsys):
        with patch.object(cli, "initialize_assessment_components") as init:
            code = self._run_main(monkeypatch, "--checks", "nope-001")

        assert code == 1
        init.assert_not_called()
        assert "unknown check ID(s) nope-001" in capsys.readouterr().out

    def test_validate_config_flag_checks_cli_values(self, monkeypatch, capsys):
        code = self._run_main(monkeypatch, "--validate-config", "--s3-bucket", "Bad_Bucket")

        assert code == 1
        assert "not a valid S3 bucket name" in capsys.readouterr().out

    @pytest.mark.parametrize(
        "extra, message",
        [
            ([], "No checkpoint for assessment abc"),
            (["--no-checkpoints"], "cannot be used with --no-checkpoints"),
        ],
    )
    def test_resume_without_checkpoint_exits(self, monkeypatch, capsys, extra, message):
        engine = Mock(checkpoint_dir="/tmp/checkpoints")
        engine.has_checkpoint.return_value = False
        with patch.object(
            cli, "initialize_assessment_components", return_value=(engine, Mock(), Mock())
        ):
            code = self._run_main(monkeypatch, "--resume-assessment", "abc", *extra)

        assert code == 1
        assert message in capsys.readouterr().out
        engine.validate_configuration.assert_not_called()
