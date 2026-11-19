import pytest
from app.models.target import Target
from app.models.session import AuditSession
from app.tools.audit_access_control import AuditAccessControlTool
from app.tools.test_input_boundaries import TestInputBoundariesTool
from app.tools.registry import ToolRegistry


def test_tool_registration():
    reg = ToolRegistry()
    assert "audit_access_control" in reg.list_tool_names()
    assert "test_input_boundaries" in reg.list_tool_names()
    
    t1 = reg.get_tool("audit_access_control")
    assert isinstance(t1, AuditAccessControlTool)
    assert t1.name == "audit_access_control"
    assert "endpoint" in t1.parameters_schema["properties"]

    t2 = reg.get_tool("test_input_boundaries")
    assert isinstance(t2, TestInputBoundariesTool)
    assert t2.name == "test_input_boundaries"
    assert "parameter_name" in t2.parameters_schema["properties"]


def test_audit_access_control_schema():
    target = Target(base_url="http://127.0.0.1:8080")
    session = AuditSession(target=target)
    tool = AuditAccessControlTool()
    assert tool.name == "audit_access_control"
    assert "endpoint" in tool.parameters_schema["required"]


def test_test_input_boundaries_schema():
    target = Target(base_url="http://127.0.0.1:8080")
    session = AuditSession(target=target)
    tool = TestInputBoundariesTool()
    assert tool.name == "test_input_boundaries"
    assert "endpoint" in tool.parameters_schema["required"]


if __name__ == "__main__":
    test_tool_registration()
    test_audit_access_control_schema()
    test_test_input_boundaries_schema()
    print("All critical security tool tests passed successfully!")
