import re

def remove_numeric_lines(input_file, output_file):
    with open(input_file, 'r') as file_in, open(output_file, 'w') as file_out:
        for line in file_in:
            # 使用正则表达式匹配是否只包含数字
            if not re.match(r'^\\\d+$', line.strip()):
                file_out.write(line)

# 使用示例
input_file = 'output.log'  # 输入的log文件名
output_file = 'output1.log'  # 去除纯数据行后的log文件名

remove_numeric_lines(input_file, output_file)
