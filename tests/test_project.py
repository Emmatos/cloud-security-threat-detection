
import importlib


def test_ingestion_module_loads():
    module = importlib.import_module("src.ingestion")
    assert callable(module.load_cloudtrail)
    assert callable(module.load_vpc_flow_logs)


def test_detection_engine_module_loads():
    module = importlib.import_module("src.detection_engine")
    assert module is not None


def test_storage_module_loads():
    module = importlib.import_module("src.storage")
    assert callable(module.save_findings)
    assert callable(module.get_findings)
