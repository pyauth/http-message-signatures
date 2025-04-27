#!/usr/bin/env python

from setuptools import find_packages, setup  # type: ignore

setup(
    name="http-msg-sig",
    url="https://github.com/tinymahua/http-message-signatures",
    license="Apache License 2.0",
    author="Andrey Kislyuk, Tiny Twist",
    author_email="kislyuk@gmail.com, tinymahua@gmail.com",
    description="An implementation of the IETF HTTP Message Signatures draft standard, forked from `http-message-signatures`",
    long_description=open("README.rst").read(),
    use_scm_version={
        "write_to": "http_msg_sig/version.py",
    },
    setup_requires=["setuptools_scm >= 3.4.3"],
    install_requires=["http-sfv >= 0.9.3", "cryptography >= 36.0.2"],
    extras_require={
        "tests": [
            "flake8",
            "coverage",
            "build",
            "wheel",
            "mypy",
            "requests",
            "ruff",
        ]
    },
    packages=find_packages(exclude=["test"]),
    include_package_data=True,
    package_data={
        "http_msg_sig": ["py.typed"],
    },
    platforms=["MacOS X", "Posix"],
    test_suite="test",
    classifiers=[
        "Intended Audience :: Developers",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
