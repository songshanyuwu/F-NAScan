# -*- coding:utf-8 -*-
#original author:wolf@future-sec                       

import getopt        #getopt 模块，是专门用来处理命令行参数的 
import sys,os,re,time
import queue         #Queue模块实现了多生产者、多消费者队列
import threading     #threading模块是Python里面常用的线程模块，多线程处理任务对于提升效率非常重要
import socket        #socket通常也叫做“套接字”，用于连接server client，是一个通信链的句柄，应用程序通常通过套接字向网络发出请求或应答网络请求。
import struct        #处理二进制数据，比如，存取文件，socket操作时，处理c语言中的结构体
import ssl           #ssl模块是网络请求重要的部分，会影响pip安装进程，django, flask等网络开发模块的使用等
import array
from urllib import request,error

startime=time.time()
queue = queue.Queue()
mutex = threading.Lock()
timeout = 10
port_list = []
re_data = {}
port_data = {}
statistics = {}
IPS = {}



#大概是创建不验证的https_context
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context



#修改了python的默认stdout输出，使得python的输出默认编码为utf8
class UnicodeStreamFilter:
    def __init__(self, target):
        self.target = target
        self.encoding = 'utf-8'
        self.errors = 'replace'
        self.encode_to = self.target.encoding
    def write(self, s):
        if type(s) == str:
            s = s.decode("utf-8")
        s = s.encode(self.encode_to, self.errors).decode(self.encode_to)
        self.target.write(s)
if sys.stdout.encoding == 'cp936':
    sys.stdout = UnicodeStreamFilter(sys.stdout)



class SendPingThr(threading.Thread):
    def __init__(self, ipPool, icmpPacket, icmpSocket, timeout=3):
        threading.Thread.__init__(self)
        self.Sock = icmpSocket
        self.ipPool = ipPool
        self.packet = icmpPacket
        self.timeout = timeout
        self.Sock.settimeout(timeout + 1)

    def run(self):
        time.sleep(0.01)
        for ip in self.ipPool:
            try:
                self.Sock.sendto(self.packet, (ip, 0))
            except socket.timeout:
                break
        time.sleep(self.timeout)



class Nscan:
    def __init__(self, timeout=3):
        self.timeout = timeout
        self.__data = struct.pack('d', time.time())
        self.__id = os.getpid()

    @property
    def __icmpSocket(self):
        Sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        return Sock

    def __inCksum(self, packet):
        if len(packet) & 1:
            packet = packet + '\0'
        words = array.array('h', packet)
        sum = 0
        for word in words:
            sum += (word & 0xffff)
        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        return (~sum) & 0xffff

    @property
    def __icmpPacket(self):
        header = struct.pack('bbHHh', 8, 0, 0, self.__id, 0)
        packet = header + self.__data
        chkSum = self.__inCksum(packet)
        header = struct.pack('bbHHh', 8, 0, chkSum, self.__id, 0)
        return header + self.__data

    def mPing(self, ipPool):
        Sock = self.__icmpSocket
        Sock.settimeout(self.timeout)
        packet = self.__icmpPacket
        recvFroms = set()
        sendThr = SendPingThr(ipPool, packet, Sock, self.timeout)
        sendThr.start()
        while True:
            try:
                ac_ip = Sock.recvfrom(1024)[1][0]
                if ac_ip not in recvFroms:
                    log("active",ac_ip,0)
                    recvFroms.add(ac_ip)
            except Exception:
                pass
            finally:
                if not sendThr.isAlive():
                    break
        return recvFroms & ipPool



def get_ac_ip(ip_list):
    try:
        s = Nscan()
        #set:类似dict，是一组key的集合， 不存储value。本质：无序和无重复的集合；创建set需要一个list或者tuple或者dict作为输入集合；重复元素在set中会自动过滤
        ipPool = set(ip_list)
        return s.mPing(ipPool)
    except:
        print('The current user permissions unable to send icmp packets')
        return ip_list



class ThreadNum(threading.Thread):
    def __init__(self,queue):
        threading.Thread.__init__(self)
        self.queue = queue
    def run(self):
        while True:
            try:
                if queue.empty() : break
                queue_task = self.queue.get()
            except:
                break
            try:
                task_host,task_port = queue_task.split(":")
                data = scan_port(task_host,task_port)
                if data:
                    #将有返回结果的数据保存到字典port_data中，key格式‘IP：port’，value格式‘返回的数据’
                    if data != 'NULL':
                        port_data[task_host + ":" + task_port] = data
                        #print('port_data:',port_data)
                    # 判断IP 端口的服务类型，即端口指纹
                    server_type = server_discern(task_host,task_port,data)
                    # server_type如果为空的处理
                    if not server_type:
                        h_server,title = get_web_info(task_host,task_port)
                        if title or h_server : server_type = 'web ' + title
                        #print(h_server,title)
                    if server_type : log('server',task_host,task_port,server_type.strip())
                    IPS[task_host + ":" + task_port] = server_type.strip()
                    #print('='*20)
            except Exception as err:
                #print(err)
                continue



def get_code(header,html):
    try:
        m = re.search(r'<meta.*?charset\=(.*?)"(>| |\/)',html, flags=re.I)
        if m:
            return m.group(1).replace('"','')
    except:
        pass
    try:
        if header.has_key('Content-Type'):
            Content_Type = header['Content-Type']
            m = re.search(r'.*?charset\=(.*?)(;|$)',Content_Type,flags=re.I)
            if m:return m.group(1)
    except:
        pass


def get_web_info(host,port):
    #h_server,h_xpb,title_str,html = '','','',''
    title_str = ''
    html = ''
    try:
        url = "http://" + host + ":" + port
        #print('start to info:',url)
        info = request.urlopen(url,timeout=timeout)
        html = info.read().decode('utf-8')
        header = info.info()
    except error.HTTPError as err:
        #header = err.headers
        header = err
    except Exception as err:
        return False,False
    if not header:return False,False
    try:
        html_code = get_code(header,html).strip()
        if html_code and len(html_code) < 12:
            html = html.decode(html_code).encode('utf-8')
    except:
        pass
    try:
        port_data[host + ":" + str(port)] = str(header)
        title = re.search(r'<title>(.*?)</title>', html, flags=re.I|re.M)
        if title:title_str=title.group(1)
    except Exception as err:
        pass
    return str(header),title_str


def scan_port(host,port):
    try:
        socket.setdefaulttimeout(timeout/2)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((str(host),int(port)))
        log('portscan',host,port)
    except Exception as err:
        #print(err)
        return False
    try:
        data = sock.recv(512)
        sock.close()
        if len(data) > 2:
            return data
        else:
            return 'NULL'
    except Exception as err:
        #print(err)
        return 'NULL'


def log(scan_type,host,port,info=''):
    # 获取互斥锁后，进程只能在释放锁后下个进程才能进来
    mutex.acquire()
    try:
        time_str = time.strftime('%X', time.localtime(time.time()))
        if scan_type == 'portscan':
            print( "[%s] %s:%d open"%(time_str,host,int(port)))
            try:
                re_data[host].append(port)
            except KeyError:
                re_data[host]=[]
                re_data[host].append(port)
        elif scan_type == 'server':
            print( "[%s] %s:%d is %s"%(time_str,host,int(port),str(info)))
            try:
                server = info.split(" ")[0].replace("(default)","")
                #统计服务类型以及数量
                statistics[server] += 1
            except KeyError:
                statistics[server] = 1
            re_data[host].remove(port)
            re_data[host].append(str(port) + " " + str(info))
        elif scan_type == 'active':
            print( "[%s] %s active"%(time_str,host))
    except Exception as err:
        #print(err)
        pass
    # 互斥锁必须被释放掉
    mutex.release()
    #print(mutex.release())


def read_config(config_type):
    if config_type == 'server_info':
        mark_list=[]
        try:
            config_file = open('server_info.ini','r')
            for mark in config_file:
                name,port,reg = mark.strip().split("|",2)
                mark_list.append([name,port,reg])
            config_file.close()
            return mark_list
        except:
            print( 'Configuration file read failed')
            exit()


def server_discern(host,port,data):
    #print('server_discern',host,port,data)
    server = ''
    # mark_list是从配置文件server_info.ini中读取的内容
    for mark_info in mark_list:
        try:
            name,default_port,reg = mark_info
            if int(default_port) == int(port):
                server = name+"(default)"
            if reg and data != 'NULL':
                matchObj = re.search(reg,data,re.I|re.M)
                if matchObj:
                    server = name
            if server:
                #print(server)
                return server
        except Exception as err:
            continue
    #print('return server:',server)
    return server


def get_ip_list(ip):
    ip_list = []
    #iptonum = lambda x:sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])
    #numtoip = lambda x: '.'.join([str(int((x/(256**i))%256)) for i in range(3,-1,-1)])
    # 如果格式是172.16.0.1-100
    if '-' in ip:
        ip_range = ip.split('-')
        #ip_start = int(iptonum(ip_range[0].split('.')[2]))
        #ip_end = int(iptonum(ip_range[1]))
        ip_start = int(ip_range[0].split('.')[2])
        ip_end = int(ip_range[1])
        ip_count = ip_end - ip_start
        if ip_count >= 0 and ip_count <= 65536:
            for ip_num in range(ip_start,(ip_end+1)):
                ip = ip_range[0].split('.')[0] + '.' + ip_range[0].split('.')[1] + '.' + ip_range[0].split('.')[2] + '.' + str(ip_num)
                ip_list.append(ip)
        else:
            print( '-h wrong format')
    # 如果是从ini文件中获取
    elif '.ini' in ip:
        ip_config = open(ip,'r')
        for ip in ip_config:
            ip_list.extend(get_ip_list(ip.strip()))
        ip_config.close()
    # 如果IP地址的格式是10.0.0.0或者10.10.0.0或者10.10.10.0的不同处理方式
    else:
        ip_split=ip.split('.')
        net = len(ip_split)
        if net == 2:
            for b in range(1,255):
                for c in range(1,255):
                    ip = "%s.%s.%d.%d"%(ip_split[0],ip_split[1],b,c)
                    ip_list.append(ip)
        elif net == 3:
            for c in range(1,255):
                ip = "%s.%s.%s.%d"%(ip_split[0],ip_split[1],ip_split[2],c)
                ip_list.append(ip)
        elif net ==4:
            ip_list.append(ip)
        else:
            print( "-h wrong format")
    return ip_list


def get_port_list(port):
    port_list = []
    if '.ini' in port:
        port_config = open(port,'r')
        for port in port_config:
            port_list.append(port.strip())
        port_config.close()
    else:
        port_list = port.split(',')
    return port_list


#处理port_data以及statistics，生成报告
def write_result():
    try:
        #获取报告生成的年月日时分秒
        now_time = time.strftime("%Y-%m-%d-%H_%M_%S",time.localtime(time.time())) 
        wenjianming = ip + "-" + now_time + ".txt"
        print('生成的文件名：',wenjianming)
        result = open(wenjianming,'w',encoding='utf-8')
        result.write('*'*20 + "检测到的 IP—端口—服务 列表" + '*'*20 + '\n')
        IPS2 = sorted(IPS.items(),key=lambda x:x[0])
        for key in IPS2:
            result.write('{:<15} {:<8} {:<25}'.format(key[0].split(':')[0],key[0].split(':')[1],key[1]) + '\n')
        
        result.write('\n' + '*'*20 + "检测到的 banner信息 列表" + '*'*20 + '\n')
        for key,value in port_data.items():
            result.write('{:<15} {:<8} {:<25}'.format(str(key).split(':')[0],str(key).split(':')[1],str(value)) + '\n')

        result.write('\n' + '*'*20 + "检测到的服务类型统计" + '*'*20 + '\n')
        result.write('服务类型  数量' + '\n')
        for key,value in statistics.items():
            result.write('{:<10} {:<8}'.format(key,value) + '\n')
        
        result.close()
    except Exception as err:
        print(err)
        print( 'Results output failure')


#应该是     用于判断进程是否都结束或者队列消耗结束
def t_join(m_count):
    tmp_count = 0
    i = 0
    while True:
        time.sleep(2)
        #获取当前活动的线程数量
        ac_count = threading.activeCount()
        #print('ac_count:',ac_count)
        #判断当前活动线程数是否小于设定线程数并且等于临时记录线程数
        if ac_count < m_count and ac_count == tmp_count:
            i+=1
        else:
            i = 0
        tmp_count = ac_count
        #print( ac_count,queue.qsize(),queue.empty(),i)
        if (queue.empty() and threading.activeCount() <= 1) or i > 5:
            break



if __name__=="__main__":
    mark_list = read_config('server_info')
    msg = '''
Scanning a network asset information script,author:wolf@future-sec.
Usage: python F-NAScan.py -h 192.168.1 [-p 21,80,3306] [-m 50] [-t 10] [-n]
    '''
    err = ''
    if len(sys.argv) < 2:
        print(msg)
    try:
        options,args = getopt.getopt(sys.argv[1:],"h:p:m:t:n")
        
        ip = ''
        noping = False
        #noping = True
        port = '21,22,23,25,53,80,110,139,143,389,443,445,465,873,993,995,1080,1723,1433,1521,3306,3389,3690,5432,5800,5900,6379,7001,8000,8001,8080,8081,8888,9200,9300,9080,9999,11211,27017'
        m_count = 100
        
        for opt,arg in options:
            if opt == '-h':
                ip = arg
            elif opt == '-p':
                port = arg
            elif opt == '-m':
                m_count = int(arg)
            elif opt == '-t':
                timeout = int(arg)
            elif opt == '-n':
                noping = True

        if ip:
            #获取ip列表和 端口列表
            ip_list = get_ip_list(ip)
            port_list = get_port_list(port)
            ipPortTime = time.time()
            #默认（not noping）结果为真，即执行icmp存活检测，结果：返回ip_list 或者 返回recvFroms & ipPool
            if not noping:ip_list=get_ac_ip(ip_list)
            #对IP地址和端口进行组合，形成队列
            for ip_str in ip_list:
                for port_int in port_list:
                    queue.put(':'.join([ip_str,port_int]))
            #测试处处队列的数量和显示队列内容
            #print('队列的数量:',queue.qsize())
            #print(queue.get())

            #在指定线程数内进行循环语句，默认m_count值为200
            for i in range(m_count):
                #
                th = ThreadNum(queue)
                #
                th.setDaemon(True)
                #
                th.start()
            
            #应该适用于判定进程是否已经运行结束
            t_join(m_count)

            saoMiaoTime = time.time()

            #将结果输出为报告
            write_result()

            #统计大概运行所花费的时间
            print('-'*10 + '大概运行时间计算' + '-'*10)
            endtime=time.time()
            print('生成IP端口列表用时：',ipPortTime-startime)
            print('ICMP + Scan 的用时：',saoMiaoTime-ipPortTime)
            print('生成文本类报告用时：',endtime-saoMiaoTime)
            print('脚本大概运行总用时：',endtime-startime)
    except Exception as err:
        #print(err)
        print( msg)

