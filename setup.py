from setuptools import setup, find_packages

setup(
    name="noobaa-sa-ci",
    version="0.1",
    packages=find_packages(),
    url="",
    license="MIT",
    author="Noobaa SA QE",
    author_email="ocs-ci@redhat.com",
    description="Noobaa Standalone(SA) CI is used to run test cases.",
    install_requires=[
        "common-ci-utils",
        "jinja2",
        "mergedeep",
        "pytest",
        "pynpm",
        "pyyaml",
        "requests",
        "boto3",
        "pytest-html",
        "py",
        "bs4",
    ],
    entry_points={
        "console_scripts": [
            "noobaa-sa-ci=framework.main:main",
        ],
    },
)
