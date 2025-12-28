# AegisMind

> Aegis(神盾) + Mind(智能大脑中枢)

恶意代码大作业，实现一个基于威胁情报分析、借助LLM分析的静态+动态分析的Web平台

## 环境配置

需要配置python环境即可运行，详细请移步至根目录下的`ENVIRONMENt.MD`

注意，我作为开发者使用的平台是Windows平台，并且使用的python版本是3.13，推荐你使用conda创建一个虚拟环境并且设置对应我的python版本。

```bash
conda create -n aegismind python=3.13
conda activate aegismind
pip install -r backend\requirements.txt
# Sigma 规则集编译可选：
pip install sigmatools
```

## 平台运行

我们需要分别开启两个终端运行前端和后端，前端运行在8000端口上：

```bash
python -m http.server 8000
```

后端则运行在8001端口上：

```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8001
```

## 关于批量运行

需要准备一个csv格式与`1.csv`格式保持相同：

|name|Is_mal|
|--|--|
|Lab06-02.exe|1|

这样我们就能够输出对应需要测试的指标。

## 关于LLM API

目前我们调用的API是

## 子文件功能与运行实例

```bash
# 扫描 "my_samples" 文件夹，并将结果保存到 "scan_report.txt"
python batch_predict.py --data_dir my_samples --output_file scan_report.txt

# 默认是位于data文件夹的内容
python batch_predict.py
```
