from setuptools import setup, find_packages

setup(
    name='certcheck',
    version='0.1.0',
    py_modules=["certcheck"],
    # packages=find_packages(),
    # include_package_data=True,
    install_requires=[
        "furl==2.1.3",
        "sslyze==5.1.3",
        "pyOpenSSL==23.1.0",
        "pytest==7.2.1",
        "pylint-exit==1.2.0",
        "pylint==2.15.9",
        "pytest-asyncio==0.20.3",
        "ocsp-checker==1.9.11"
    ],
    entry_points={
        'console_scripts': [
            'certcheck=certcheck:main',
        ]
    },
)