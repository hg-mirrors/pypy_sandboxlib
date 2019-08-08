from setuptools import setup

setup(name='sandboxlib',
      scripts=['interact.py'],
      packages=['sandboxlib'],
      setup_requires=["cffi"],
      cffi_modules=["sandboxlib/_commonstruct_build.py:ffibuilder"],
      install_requires=["cffi"],
      )
