from framework import config


def pytest_addoption(parser):
    parser.addoption("--conf", action="append", default=[])
    parser.addoption(
        "--email",
        dest="email",
        help="Email ID to send results",
    )
