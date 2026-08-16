from setuptools import setup

setup(
    name="arch-map",
    version="1.0.0",
    description="Fast, zero-config CLI that statically scans any codebase to generate visual architecture mental models in Markdown.",
    author="Thupten Wangpo",
    url="https://github.com/Dodhon/arch-map",
    py_modules=["arch_map"],
    entry_points={
        "console_scripts": [
            "arch-map=arch_map:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
