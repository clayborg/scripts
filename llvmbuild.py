#!/usr/bin/env python3

import sys
import subprocess
import optparse
import platform

# See https://www.internalfb.com/code/osmeta-infrastructure-toolchain-build/tools/sand/python_tester/python_tester_wrapper
python_path_dirs = [
    "/mnt/gvfs/third-party2/appdirs/8530981bc35a4518dda153a078877f65565703d8/1.4.0/platform010/de3fdd4/lib/python",
    "/mnt/gvfs/third-party2/setuptools/bc68d12afde642aed6e9dca90b88853e534f9248/34.2.0/platform010/d5b5d79/lib/python",
    "/mnt/gvfs/third-party2/six/3410c43c9144c88f88d59d7e8fea1b344fce85ce/1.10.0/platform010/de3fdd4/lib/python",
    "/mnt/gvfs/third-party2/python-packaging/520276b50788018bf2be4ad41bfed8983e7b5ebd/16.8/platform010/0dae1d8/lib/python",
    "/mnt/gvfs/third-party2/psutil/cf7522d8b8051f0c75dd0d6b82dc4067b22e4145/5.8.0/platform010/de3fdd4/lib/python",
    "/mnt/gvfs/third-party2/pyparsing/1fe276f7d898971d2e35e39fc41cb1221c497745/2.1.10/platform010/de3fdd4/lib/python",
    "/mnt/gvfs/third-party2/ptyprocess/19fc309addeb16011fc0a8ba4a221feb875d487c/0.5.1/platform010/aca4734/lib/python",
    "/mnt/gvfs/third-party2/pexpect/460616b87f8efe25040d74f78bb4f2fa4671998e/4.6.0/platform010/cf30119/lib/python",
]
python_path=":".join(python_path_dirs)

default_python_src_dir = '~/Library/Python/3.9/lib/python/site-packages'
default_python_dst_dir = 'dev:~/local/github/Debug/lib/python3.10/site-packages'
default_lldb_dst_build_dir = '~/local/github/Debug'
python_module_names = ["packaging", "pexpect", "ptyprocess", "psutil"]
def main():
    parser = optparse.OptionParser(
        description='A helper script to checkout, configure and build llvm projects',
        prog='llvmbuild',
        usage='llvmbuild [options]',
        add_help_option=True)

    parser.add_option(
        '--cmake',
        type='string',
        dest='cmake',
        help='The path to the cmake binary to use',
        default='cmake')

    parser.add_option(
        '--target',
        type='string',
        dest='target',
        help='The target platform name ("Darwin",or "Linux"). Defaults to current OS platform system.',
        default=None)

    parser.add_option(
        '--platform-dir',
        type='string',
        dest='devserver_platform_dir',
        help='Devserver platform path. Detaults to "/usr/local/fbcode/platform010".',
        default='/usr/local/fbcode/platform010')

    parser.add_option(
        '--llvm-dir',
        type='string',
        dest='llvm_dir',
        help='Path to the llvm source directory. Defaults to "../llvm-project/llvm".',
        default='../llvm-project/llvm')

    parser.add_option(
        '--python-src-dir',
        type='string',
        dest='python_src_dir',
        help=f'Path to the python directory on the current machine to copy from. Defaults to "{default_python_src_dir}".',
        default=default_python_src_dir)

    parser.add_option(
        '--python-dst-dir',
        type='string',
        dest='python_dst_dir',
        help=f'Path to the python directory on the remote machine to copy tp. Defaults to "{default_python_dst_dir}".',
        default=default_python_dst_dir)

    parser.add_option(
        '--clang',
        type='string',
        dest='clang',
        help='Path to the clang compiler.',
        default=None)

    parser.add_option(
        '--build',
        type='string',
        dest='build',
        help='The cmake build type (Debug, Release, RelWithDbgInfo). Defaults to "Debug".',
        default='Debug')

    parser.add_option(
        '--dry-run', '-d',
        action='store_true',
        dest='dryrun',
        default=False,
        help="Don't actually run commands, just print them.")

    parser.add_option(
        '--pythonpath', '-p',
        action='store_true',
        dest='pythonpath',
        default=False,
        help='Print out the python path needed for devservers.')
    parser.add_option(
        '--python-packages', '-O',
        action='store_true',
        dest='pythonpackages',
        default=False,
        help='Print out the python package rsync commands needed for on devservers.')

    (options, args) = parser.parse_args(sys.argv[1:])

    if options.pythonpath:
        print(f'PYTHONPATH={python_path}')
        return
    if options.pythonpackages:
        python_rsync_commands = []
        for python_module_name in python_module_names:
            python_rsync_commands.append("rsync -av '${options.python_src_dir}/{python_module_name}' '${python_dst_dir}'")
        for python_rsync_command in python_rsync_commands:
            print(python_rsync_command)
        return
    devserver_platform_dir = '/usr/local/fbcode/platform010'
    if options.target is None:
        options.target = platform.system()
    if options.clang is None:
        if options.target == 'Linux':
            options.clang = '/opt/llvm/stable/Toolchains/llvm-sand.xctoolchain/usr/bin/clang'
    cmake_info = {
        'common': {
            'options': [
                '-G Ninja',
                '-DLLVM_OPTIMIZED_TABLEGEN:BOOL=TRUE',
                "-DLLVM_ENABLE_PROJECTS='clang;lldb;lld'",
                "-DLLVM_ENABLE_RUNTIMES='libcxx;libcxxabi;libunwind'",
                '-DLLVM_ENABLE_ASSERTIONS:BOOL=TRUE',
                '-DLLDB_EDITLINE_USE_WCHAR=0',
                '-DLLDB_ENABLE_LIBEDIT:BOOL=TRUE',
                '-DLLDB_ENABLE_CURSES:BOOL=TRUE',
                '-DLLDB_ENABLE_PYTHON:BOOL=TRUE',
                '-DLLDB_ENABLE_LIBXML2:BOOL=TRUE',
                '-DLLDB_ENABLE_LUA:BOOL=FALSE',
            ],
        },
        'builds': {
            'Debug': {
                'options': [
                    '-DCMAKE_BUILD_TYPE:STRING=Debug',
                    "-DCMAKE_CXX_FLAGS_DEBUG='-O0 -glldb'",
                ]
            },
            'RelWithDebInfo': {
                'options': [
                    '-DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo',
                    "-DCMAKE_CXX_FLAGS_DEBUG='-glldb'",
                ]
            },
            'Release': {
                'options': [
                    '-DCMAKE_BUILD_TYPE:STRING=Release',
                ]
            }
        },
        'platform' : {
            'Darwin': {
                'options': [
                    '-DLLDB_BUILD_FRAMEWORK:BOOL=TRUE',
                    '-DLLDB_USE_SYSTEM_DEBUGSERVER=ON',
                    '-DPython3_EXECUTABLE=/usr/bin/python3'
                ]
            },
            'Linux': {
                'options': [
                    f"-DCMAKE_EXE_LINKER_FLAGS='-L {options.devserver_platform_dir} -L /usr/lib64 -Xlinker --dynamic-linker -Xlinker {options.devserver_platform_dir}/lib/ld.so'",
                    '-DLLVM_ENABLE_LLD=ON',
                    '-DCMAKE_BUILD_WITH_INSTALL_RPATH:BOOL=TRUE',
                    f'-DCMAKE_BUILD_RPATH:STRING={options.devserver_platform_dir}/lib:$ORIGIN/../lib:$ORIGIN/../../../../lib:/usr/lib64',
                    f'-DCMAKE_INSTALL_RPATH={options.devserver_platform_dir}/lib:$ORIGIN/../lib:$ORIGIN/../../../../lib:/usr/lib64',
                    f'-DPython3_EXECUTABLE={options.devserver_platform_dir}/bin/python3.10',
                    # '-DLLDB_ENABLE_LIBXML2:BOOL=FALSE',
                ]
            }
        }
    }

    cmake_args = [options.cmake, options.llvm_dir]
    # Add common options
    cmake_args.extend(cmake_info['common']['options'])
    if options.build not in cmake_info['builds']:
        print('error: build "%s" is not supported by this script')
        return 0
    cmake_args.extend(cmake_info['builds'][options.build]['options'])
    if options.target not in cmake_info['platform']:
        print(f'error: platform "{options.target}" is not supported by this script')
        return 0
    cmake_args.extend(cmake_info['platform'][options.target]['options'])

    if options.clang is not None:
        cmake_args.extend([
            '-DCMAKE_ASM_COMPILER_ID=Clang',
            f'-DCMAKE_ASM_COMPILER={options.clang}',
            f'-DCMAKE_CXX_COMPILER={options.clang}++',
            f'-DCMAKE_C_COMPILER={options.clang}',
        ])
    if options.dryrun:
        for arg in cmake_args:
            print(arg)
    else:
        print(' '.join(cmake_args))
        subprocess.call(cmake_args)

if __name__ == '__main__':
    main()
