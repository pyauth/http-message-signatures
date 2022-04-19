#!/usr/bin/env python

from setuptools import setup, find_packages  # type: ignore

setup(
    name='http-message-signatures',
    url='https://github.com/pyauth/http-message-signatures',
    license='Apache Software License',
    author='Andrey Kislyuk',
    author_email='kislyuk@gmail.com',
    description="An implementation of the IETF HTTP Message Signatures draft standard",
    long_description=open('README.rst').read(),
    use_scm_version={
        "write_to": "http_message_signatures/version.py",
    },
    setup_requires=['setuptools_scm >= 3.4.3'],
    install_requires=[
        "http-sfv >= 0.9.3",
        "cryptography >= 36.0.2"
    ],
    extras_require={
        "tests": [
            "flake8",
            "coverage",
            "build",
            "wheel",
            "mypy",
            "requests",
        ]
    },
    packages=find_packages(exclude=['test']),
    include_package_data=True,
    package_data={
        "http_message_signatures": ["py.typed"],
    },
    platforms=['MacOS X', 'Posix'],
    test_suite='test',
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
)
