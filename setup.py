from setuptools import setup, find_packages


__title__ = "domainchecker"
__version__ = "0.5.0"
__author__ = "Petter Andreas Strøm"
__email__ = "pastrom@gmail.com"
__uri__ = "https://github.com/pastrom/domainchecker"
__summary__ = "Framework for automating domain and endpoint checks (including nslookup, ports, Qualys SSL Labs etc."

__requirements__ = [
    "requests>=2.13.0",
    "elasticsearch>=7.0.0",
    "pytz>=2019.3",
    "tld>=0.11.11",
]

__entry_points__ = {
    "console_scripts": [
        "domain-checker = domainchecker.main:main",
    ]
}

CLASSIFIERS = [
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3 :: Only",
]

setup(
    author=__author__,
    author_email=__email__,
    classifiers=CLASSIFIERS,
    data_files=[
        ("", ["ReleaseNotes.md"]),
    ],
    description=__summary__,
    entry_points=__entry_points__,
    install_requires=__requirements__,
    name=__title__,
    packages=find_packages(exclude=["tests"]),
    python_requires=">=3.6",
    url=__uri__,
    version=__version__,
    zip_safe=False,
)
