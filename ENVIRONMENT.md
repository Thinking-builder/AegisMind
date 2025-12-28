# 环境设置与验证

## 当前机器快照（开发者的平台）
- 操作系统: Microsoft Windows 11 Pro (Build 22631), ARM64
- Python: 3.13.3
- pip: 25.3

## 已安装的 Python 包（关键运行时）
- fastapi==0.115.5
- uvicorn==0.32.0
- python-multipart==0.0.9
- yara-python==4.5.4
- pyyaml==6.0.3
- python-evtx==0.8.1
- httpx==0.28.1
- torch==2.9.1

## 脚本使用的开发/工具包
- sigmatools==0.23.1 (提供 `compile_sigma_ruleset.py` 使用的 `sigma.sigmac`)

## 外部工具（捆绑在仓库中）
- YARA: `backend/yara.exe`
- Zircolite: `backend/zircolite_win/zircolite_win_x64_2.40.0.exe`
- EVTX dump helper: `backend/zircolite_win/bin/evtx_dump_win.exe`
- Zircolite 映射: `backend/zircolite_win/config/fieldMappings.json`

## requirements.txt 兼容性检查
文件: `backend/requirements.txt`

以下包的已安装版本与 `requirements.txt` 中锁定的版本不匹配：
- fastapi (已安装 0.115.5 vs 锁定 0.110.0)
- uvicorn (已安装 0.32.0 vs 锁定 0.24.0.post1)
- yara-python (已安装 4.5.4 vs 锁定 4.3.1)
- pyyaml (已安装 6.0.3 vs 锁定 6.0.1)
- python-evtx (已安装 0.8.1 vs 锁定 0.6.1)
- httpx (已安装 0.28.1 vs 锁定 0.26.0)
- torch (已安装 2.9.1 vs 锁定 2.1.2)

匹配项：
- python-multipart (已安装 0.0.9 匹配 锁定 0.0.9)

注意：
- `sigmatools` 未列在 `requirements.txt` 中，但如果运行 `compile_sigma_ruleset.py` 则需要它。
- 如果您想要一个干净、可复现的环境，请更新 `requirements.txt` 以匹配已安装的版本，或者创建一个新的虚拟环境并安装锁定的版本。

## 推荐设置（干净的虚拟环境）
```bash
conda create -n aegismind python=3.13
conda activate aegismind
pip install -r backend\requirements.txt
# Sigma 规则集编译可选：
pip install sigmatools
```

