#网络资产信息扫描<br>
<br>
目的：通过将程序运行版本由Python2升级为Python3来学习原作者ywolf的F-NAScan实现功能。<br>
<br>
在渗透测试(特别是内网)中经常需要对目标进行网络资产收集，即对方服务器都有哪些IP，IP上开了哪些端口，端口上运行着哪些服务。<br>
此脚本即为实现此过程，相比其他探测脚本有以下优点：<br>
      1、轻巧简洁,只需python环境，无需安装额外外库。<br>
      2、扫描完成后生成独立页面报告。<br>
<br>
此脚本的大概流程为 ICMP存活探测-->端口开放探测-->端口指纹服务识别-->提取快照(若为WEB)-->生成结果报表<br>
<br>
运行环境:python 3.7 +<br>
<br>
参数说明<br>
-h 必须输入的参数，最多限制一次可扫描65535个IP。<br>
      支持ip(192.168.1.1)<br>
      ip段（192.168.1）<br>
      ip范围指定（192.168.1.1-192.168.1.254）<br>
      ip列表文件（ip.ini）<br>
-p 指定要扫描端口列表，多个端口使用,隔开  <br>
      例如：22,23,80,3306。<br>
      未指定即使用内置默认端口进行扫描<br>(21,22,23,25,53,80,110,139,143,389,443,445,465,873,993,995,1080,1723,1433,1521,3306,3389,3690,5432,5800,5900,6379,7001,8000,8001,8080,8081,8888,9200,9300,9080,9999,11211,27017)<br>
-m 指定线程数量 默认100线程<br>
-t 指定HTTP请求超时时间，默认为10秒，端口扫描超时为值的1/2。<br>
-n 不进行存活探测(ICMP)直接进行扫描。<br>
-o 指定文件名的部分。<br>
    结果报告保存在当前目录(扫描IP-文件名-时间戳.html)。<br>
<br>
结果报告保存在当前目录(扫描IP-时间戳.html)。<br>
<br>
使用例子：<br>
python NAScan.py -h 10.111.1<br>
python NAScan.py -h 192.168.1.1-192.168.2.111<br>
python NAScan.py -h 10.111.1.22 -p 80,7001,8080 -m 200 -t 6<br>
python NAScan.py -h ip.ini -p port.ini -n<br>
<br>
服务识别在server_info.ini文件中配置<br>
格式为：服务名|默认端口|正则  例 ftp|21|^220.*?ftp|^220-<br>
正则为空时则使用端口进行匹配，否则以正则匹配结果为准。<br>
<br>
项目地址 https://github.com/ywolf/<br>
欢迎大家反馈建议和BUG<br>
<br>
