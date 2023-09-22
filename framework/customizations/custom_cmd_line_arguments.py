def pytest_addoption(parser):
    parser.addoption("--conf", action="append", default=[])
