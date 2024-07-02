# 处理从 origin1.txt 到 origin100.txt 的数据
for i in range(1, 11):
    # 构建原始数据文件名和目标数据文件名
    origin_filename = f'inject_data{i}.txt'
    data_filename = f'inject_time{i}.txt'

    # 打开原始数据文件
    with open(origin_filename, 'r') as f:
        lines = f.readlines()

    # 分割每一行数据，并写入目标数据文件中
    with open(data_filename, 'w') as f:
        for line in lines:
            parts = line.split()
            if len(parts) == 2:
                f.write(parts[1] + '\n')
