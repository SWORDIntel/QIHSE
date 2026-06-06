from setuptools import setup, Extension
import os

qihse_ext = Extension(
    'qihse',
    sources=['qihse.c'],
    include_dirs=[
        '../../include', 
        '../../vendor/tree-sitter/lib/include',
        '../../algorithms',
        '../../core',
        '../../persistence',
        '../../codecs',
        '../../memory/include',
        '../../orchestration/include',
        '../../ml/include',
        '../../quantization/include',
        '../../msnet'
    ],
    library_dirs=['../../'],
    libraries=['qihse'],
    extra_compile_args=['-O3', '-std=c99']
)

setup(
    name='qihse',
    version='1.0.0',
    description='Native Python C-Bindings for QIHSE',
    ext_modules=[qihse_ext],
)
