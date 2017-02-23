from setuptools import setup, Extension
from distutils.command.build import build
from setuptools.command.install import install

class CustomBuild(build):
    def run(self):
        self.run_command('build_ext')
        build.run(self)

class CustomInstall(install):
    def run(self):
        self.run_command('build_ext')
        self.do_egg_install()


swig_ext = Extension('sdhash._sdbf_class',
    #define_macros = [('BOOST_THREAD_USE_LIB', '1')],
    sources = ['sdbf.i'],
    libraries = ['sdbf', 'boost_system', 'boost_filesystem', 'boost_program_options', 'c', 'crypto', 'boost_thread', 'pthread', 'protobuf'],
    library_dirs = ['../../external/stage/lib'],
    extra_compile_args = ['-fopenmp', '-I../../external'],
    extra_link_args = ['-fopenmp'],
    swig_opts=['-c++'])

setup(
    name='sdhash',
    version='0.0.1',
    description='SDHash python wrapper',
    url='https://github.com/sdhash/sdhash',
    author='Jonas Zaddach',
    author_email='jzaddach@cisco.com',
    long_description = "SDHash python wrapper",
    cmdclass={'build': CustomBuild, 'install': CustomInstall},
    packages=[
        'sdhash',
    ],
    package_dir={'sdhash': ''},
    ext_modules = [swig_ext],
    install_requires = [],
    setup_requires = [],
    tests_require = [],
)
