from adbygod_api.models import OffensiveJob, JobOutput, OpsecProfile, OffensiveJobStatus


def test_opsec_profile_enum_values():
    assert OpsecProfile.LOUD == "LOUD"
    assert OpsecProfile.BALANCED == "BALANCED"
    assert OpsecProfile.GHOST == "GHOST"


def test_offensive_job_status_enum_values():
    assert OffensiveJobStatus.PENDING == "PENDING"
    assert OffensiveJobStatus.RUNNING == "RUNNING"
    assert OffensiveJobStatus.COMPLETED == "COMPLETED"
    assert OffensiveJobStatus.FAILED == "FAILED"
    assert OffensiveJobStatus.KILLED == "KILLED"


def test_offensive_job_has_required_columns():
    cols = {c.key for c in OffensiveJob.__table__.columns}
    for col in ["id", "assessment_id", "technique_id", "target", "params",
                "executor", "opsec_profile", "status", "owner_user_id",
                "created_at", "started_at", "completed_at", "exit_code"]:
        assert col in cols, f"Missing column: {col}"


def test_job_output_has_required_columns():
    cols = {c.key for c in JobOutput.__table__.columns}
    for col in ["id", "job_id", "stream", "line", "ts"]:
        assert col in cols, f"Missing column: {col}"
