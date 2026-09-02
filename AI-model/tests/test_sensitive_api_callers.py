from app.extractors.sensitive_api_callers import scan_sensitive_api_callers


class FakeMethod:
    def __init__(self, class_name, name, descriptor="()V", xrefs=()):
        self.class_name = class_name
        self.name = name
        self.descriptor = descriptor
        self._xrefs = list(xrefs)

    def get_xref_to(self):
        return list(self._xrefs)


class FakeAnalysis:
    def __init__(self, methods):
        self._methods = methods

    def get_methods(self):
        return list(self._methods)


def test_xref_scan_records_caller_identity_and_offset():
    sensitive = FakeMethod("Ljava/lang/Runtime;", "exec")
    caller = FakeMethod(
        "Lcom/example/ExportedService;",
        "onStartCommand",
        "(Landroid/content/Intent;II)I",
        xrefs=[(None, sensitive, 12)],
    )

    result = scan_sensitive_api_callers(FakeAnalysis([caller, sensitive]))

    assert result.status == "complete"
    assert result.error_count == 0
    assert result.callers == [{
        "group_id": "SENSITIVE_API_CODE_EXEC",
        "group_label": "命令執行 / 反射 / 動態載入 API",
        "api_class": "java/lang/Runtime",
        "api_method": "exec",
        "description": "執行系統命令",
        "caller_class": "Lcom/example/ExportedService;",
        "caller_method": "onStartCommand",
        "caller_descriptor": "(Landroid/content/Intent;II)I",
        "call_offset": 12,
        "source": "androguard_xref",
    }]


def test_xref_scan_requires_both_class_and_method_match():
    unrelated_start = FakeMethod("Lcom/example/Worker;", "start")
    caller = FakeMethod(
        "Lcom/example/MainActivity;",
        "onCreate",
        xrefs=[(None, unrelated_start, 2)],
    )

    result = scan_sensitive_api_callers(FakeAnalysis([caller]))

    assert result.status == "complete"
    assert result.callers == []


def test_missing_analysis_is_unknown_instead_of_zero_evidence():
    result = scan_sensitive_api_callers(None)

    assert result.status == "unavailable"
    assert result.error_count == 1
    assert result.callers == []
