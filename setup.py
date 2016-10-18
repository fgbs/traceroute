#!/usr/bin/env python

from distutils.core import setup

try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except (IOError, ImportError):
    long_description = 'Traceroute and Geolocation'


classifiers = [
    "Intended Audience :: Developers",
    "Intended Audience :: Information Technology",
    "Intended Audience :: System Administrators",
    "Intended Audience :: Telecommunications Industry",
    "License :: OSI Approved :: MIT License",
    "Operating System :: MacOS",
    "Operating System :: MacOS :: MacOS X",
    "Operating System :: POSIX",
    "Operating System :: POSIX :: Linux",
    "Operating System :: Unix",
    "Programming Language :: Python",
    "Programming Language :: Python :: 2 :: Only",
    "Programming Language :: Python :: 2",
    "Programming Language :: Python :: 2.6",
    "Programming Language :: Python :: 2.7",
    "Topic :: Internet",
    "Topic :: System :: Networking",
    "Topic :: System :: Networking :: Monitoring"
]


setup(
    name='traceroute',
    version='0.2.0',
    description='Traceroute and Geolocation',
    long_description=long_description,
    author='Felipe Barros',
    url='https://github.com/fgbs/traceroute',
    license='MIT License',
    py_modules=['traceroute'],
    classifiers=classifiers
)
