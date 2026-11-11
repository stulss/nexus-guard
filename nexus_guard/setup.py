from setuptools import setup, find_packages

setup(
    name="nexus-guard",
    version="2.5.0",
    author="Hong Joo-hyung",
    author_email="stulss@github.com",
    description="AI-Powered Active Defense & Real-Time XDR Security Agent for Web Applications",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "urllib3>=1.26.0",
    ],
    entry_points={
        "console_scripts": [
            "nexus-guard=nexus_guard.cli.guard_cli:main",
        ],
    },
    classifiers=[
        "Topic :: Security",
        "Framework :: Flask",
        "Programming Language :: Python :: 3",
    ],
)
