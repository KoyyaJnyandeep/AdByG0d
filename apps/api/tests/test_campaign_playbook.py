
def test_campaign_has_7_phases():
    from adbygod_api.core.ai_operator.campaign import CAMPAIGN_PLAN, PHASES
    assert len(PHASES) == 7
    assert len(CAMPAIGN_PLAN) == 7

def test_campaign_phases_in_order():
    from adbygod_api.core.ai_operator.campaign import PHASES
    expected = ["recon", "enum", "loot", "privesc", "lateral", "da", "report"]
    assert PHASES == expected

def test_get_phase_returns_correct_phase():
    from adbygod_api.core.ai_operator.campaign import get_phase
    phase = get_phase("enum")
    assert phase is not None
    assert phase.name == "enum"
    assert "ldap" in phase.description.lower() or phase.exec_tools  # has work to do

def test_get_phase_returns_none_for_unknown():
    from adbygod_api.core.ai_operator.campaign import get_phase
    assert get_phase("unknown-phase") is None

def test_playbook_parse_yaml():
    from adbygod_api.core.ai_operator.playbook_engine import PlaybookEngine
    playbook_yaml = """
name: "Test Playbook"
description: "Simple test"
steps:
  - id: enum
    technique: ldap-full-enum
    on_success: kerberoast
    on_failure: done
  - id: kerberoast
    technique: kerberoast-spns
    on_success: done
"""
    engine = PlaybookEngine()
    pb = engine.parse(playbook_yaml)
    assert pb["name"] == "Test Playbook"
    assert len(pb["steps"]) == 2
    assert pb["steps"][0]["id"] == "enum"
    assert pb["steps"][0]["on_success"] == "kerberoast"

def test_playbook_resolve_params():
    from adbygod_api.core.ai_operator.playbook_engine import PlaybookEngine, EngineStep
    engine = PlaybookEngine()
    step = EngineStep(
        id="pth",
        technique="pth-wmiexec",
        params={"target": "{{ first_owned_machine }}", "domain": "{{ domain }}"},
        on_success="dcsync",
        on_failure="done",
    )
    resolved = engine.resolve_params(step, {"first_owned_machine": "DC01", "domain": "corp.local"})
    assert resolved["target"] == "DC01"
    assert resolved["domain"] == "corp.local"

def test_playbook_resolve_params_missing_var_keeps_placeholder():
    from adbygod_api.core.ai_operator.playbook_engine import PlaybookEngine, EngineStep
    engine = PlaybookEngine()
    step = EngineStep(
        id="test",
        technique="some-tech",
        params={"target": "{{ missing_var }}"},
        on_success="done",
        on_failure="done",
    )
    resolved = engine.resolve_params(step, {})
    assert "{{ missing_var }}" in resolved["target"] or resolved["target"] == "{{ missing_var }}"

def test_playbook_list_files(tmp_path):
    from adbygod_api.core.ai_operator.playbook_engine import PlaybookEngine
    pb_file = tmp_path / "test.yaml"
    pb_file.write_text("name: MyTest\ndescription: Test playbook\nsteps: []")
    engine = PlaybookEngine(base_dir=str(tmp_path))
    playbooks = engine.list_playbooks()
    assert any(p["name"] == "MyTest" for p in playbooks)
    assert any(p["step_count"] == 0 for p in playbooks)

def test_playbook_get_step():
    from adbygod_api.core.ai_operator.playbook_engine import PlaybookEngine
    engine = PlaybookEngine()
    pb = engine.parse("name: T\ndescription: X\nsteps:\n  - id: step1\n    technique: t1\n    on_success: done\n    on_failure: done\n")
    step = engine.get_step(pb, "step1")
    assert step is not None
    assert step["id"] == "step1"

def test_playbook_get_step_missing_returns_none():
    from adbygod_api.core.ai_operator.playbook_engine import PlaybookEngine
    engine = PlaybookEngine()
    pb = {"steps": []}
    assert engine.get_step(pb, "nonexistent") is None
