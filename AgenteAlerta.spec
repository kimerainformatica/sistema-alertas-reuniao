# -*- mode: python ; coding: utf-8 -*-
# Build: python -m PyInstaller --clean --noconfirm AgenteAlerta.spec
# Saída: dist/AgenteAlerta.exe (arquivo único, sem console).
# Coloque config.json ao lado do .exe (é o config_agente.json gerado pelo
# Servidor Central, renomeado). A logo do Instituto Acqua já vem
# embutida no código; para trocá-la, coloque um "logo.png" ao lado do .exe.

a = Analysis(
    ['agente_cliente.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['PIL._tkinter_finder'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'openpyxl', 'et_xmlfile', 'cryptography',
        'unittest', 'pydoc', 'doctest', 'test', 'lib2to3', 'xmlrpc', 'pdb',
        'distutils', 'setuptools', 'pip', 'tkinter.test',
    ],
    noarchive=False,
    optimize=2,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='AgenteAlerta',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
