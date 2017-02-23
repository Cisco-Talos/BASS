from setuptools import Extension, setup


lcs_ext = Extension('cisco.bass.algorithms._lcs',
    define_macros = [],
    include_dirs = [],
    libraries = [],
    sources = ['src/_lcs.cpp'],
    extra_compile_args = ['-std=c++11'])

setup(
    name='bass',
    version='0.0.1',
    description='BASS automated signature synthesizer',
    url='https://git.vrt.sourcefire.com/MALWARE-TEAM/bass',
    author='Mariano Graziano, Jonas Zaddach',
    author_email='magraziano@cisco.com, jzaddach@cisco.com',
    long_description = "Automatically build ClamAV signatures from malware samples",
    packages=[
        'cisco',
        'cisco.bass',
        'cisco.bass.algorithms',
        'cisco.bass.docker',
        'cisco.bass.resources',
        'cisco.bass.avclass',
    ],
    package_data={
        'cisco.bass.resources': ['dummy.hsb'],
        'cisco.bass.avclass' : ['*.json','default.*'],
    },
    ext_modules = [lcs_ext],
    install_requires = [
            'requests', 
            'futures', 
            'python-magic',
            'pefile',
            'virustotal-api',
            'pygraphviz',
            'networkx'],
    setup_requires = ['pytest-runner'],
    tests_require = ['pytest'],
)
