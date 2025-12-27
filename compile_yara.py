import yara
import os

# 配置路径
RULES_DIR = 'yara_rules'
OUTPUT_DIR = 'compiled_rules'
OUTPUT_FILENAME = 'all_rules.yac'

def compile_rules():
    # 确保输出目录存在
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    valid_filepaths = {}
    skipped_files = []
    
    print(f"正在扫描 {RULES_DIR} 目录下的规则文件...")

    # 第一步：遍历并验证每个文件
    for root, dirs, files in os.walk(RULES_DIR):
        for file in files:
            if file.endswith('.yar'):
                full_path = os.path.join(root, file)
                namespace = file.replace('.', '_').replace('-', '_').replace(' ', '_')
                
                try:
                    # 尝试单独编译每个文件以验证其有效性
                    # 注意：这里不保存，只是为了检查语法和依赖
                    yara.compile(filepath=full_path)
                    valid_filepaths[namespace] = full_path
                except yara.Error as e:
                    # 如果编译失败（例如缺少 androguard 模块），则跳过
                    # print(f"跳过文件 {file}: {e}") # 减少输出噪音，只统计数量
                    skipped_files.append(file)

    if not valid_filepaths:
        print("未找到任何有效的 .yar 文件。")
        return

    print(f"\n扫描完成。")
    print(f"有效规则文件: {len(valid_filepaths)}")
    print(f"跳过规则文件: {len(skipped_files)} (通常是因为缺少 androguard/cuckoo 等特定模块)")
    
    print(f"正在将所有有效规则编译为一个文件...")

    try:
        # 批量编译所有有效规则
        rules = yara.compile(filepaths=valid_filepaths)
        
        output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILENAME)
        rules.save(output_path)
        
        print(f"\n编译成功！")
        print(f"已保存至: {output_path}")
        print(f"你可以使用 rules = yara.load('{output_path}') 来加载使用。")

    except Exception as e:
        print(f"最终合并编译时发生错误:")
        print(e)

if __name__ == '__main__':
    compile_rules()
