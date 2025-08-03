from setuptools import setup, Extension

setup(
    name="cycles",
    ext_modules=[
        Extension("cycles", ["cycles.c"])
    ]
)
