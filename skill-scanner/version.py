import subprocess
import json

# 获取所有环境
result = subprocess.run(['conda', 'env', 'list', '--json'], capture_output=True, text=True)
envs = json.loads(result.stdout)

print("Conda环境Python版本列表：")
print("-" * 40)

for env in envs['envs']:
    env_name = env.split('/')[-1]  # 获取环境名称
    if env_name == 'envs':
        env_name = 'base'

    try:
        # 获取该环境的Python版本
        version = subprocess.run(
            ['conda', 'run', '-n', env_name, 'python', '--version'],
            capture_output=True, text=True, timeout=5
        )
        print(f"{env_name}: {version.stdout.strip()}")
    except:
        print(f"{env_name}: 无法获取版本信息")