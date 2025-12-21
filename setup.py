from setuptools import setup, find_packages

setup(
    name="vuln-scanner",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "python-nmap>=0.7.1",
        "requests>=2.28.0",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "vulnscan=vuln_scanner.main:main",
        ],
    },
)