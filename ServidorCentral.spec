# -*- mode: python ; coding: utf-8 -*-
# Build: python -m PyInstaller --clean --noconfirm ServidorCentral.spec
# Saída: dist/ServidorCentral.exe (arquivo único, sem console).
# relatorios_assinados.csv, alertas_emitidos.jsonl, servidor.log, config.json,
# config_agente.json e o certificado TLS (servidor_cert.pem/servidor_chave.pem)
# ficam ao lado do .exe.

a = Analysis(
    ['servidor_central.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['PIL._tkinter_finder', 'openpyxl', 'openpyxl.styles', 'openpyxl.cell._writer'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
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
    name='ServidorCentral',
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
