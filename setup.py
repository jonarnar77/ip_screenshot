from setuptools import setup, find_packages

setup(
    name="ip-screenshot-scanner",
    version="1.0.0",
    description="Scan IPs for web servers, capture screenshots, and generate galleries.",
    author="Jon Arnar Jonsson",
    license="MIT",
    packages=find_packages(),
    py_modules=["ip_screenshot"],
    install_requires=[
        "selenium",
        "webdriver-manager",
        "Pillow",
    ],
    entry_points={
        "console_scripts": [
            "ip-screenshot=ip_screenshot:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)
