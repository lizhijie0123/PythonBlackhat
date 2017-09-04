#/usr/bin/python
#--coding:utf-8--
"""多线程，使用TCP全连接，解析目标主机并扫描目标端口"""
import optparse
import sys
from socket import *
from threading import Semaphore, Thread

import nmap


screenLock = Semaphore(value=1)


def connectScan(tHost, tPort):
    """使用完整的TCP连接，确定主机目标端口时候开启。
    使用多线程的时候，通过信号量来控制打印时线程阻塞"""
    try:
        connectsocket = socket(AF_INET, SOCK_STREAM)
        connectsocket.connect((tHost, tPort))
        connectsocket.send('Testfrompython\r\n')
        results = connectsocket.recv(250)
        screenLock.acquire()
        print('[+]%d/tcp端口开启' % tPort)
        print('[+] ' + str(results))
    except Exception as e:
        screenLock.acquire()
        print('[-]%d/tcp端口关闭' % tPort + '\n异常：' + str(e))
    finally:
        screenLock.release()
        connectsocket.close()


def nmapScan(tIP, tPort):
    """使用Nmap进行基本的扫描"""
    nmScan = nmap.PortScanner()
    nmScan.scan(tIP, tPort)
    state = nmScan[tIP]['tcp'][int(tPort)]['state']
    screenLock.acquire()
    print('[*] ' + tIP + ' tcp/' + tPort + ' ' + state)
    screenLock.release()


def portScan(tHost, tPorts):
    """解析主机IP，同时对传入的每个端口进行扫描（使用多线程）"""
    try:
        tIP = gethostbyname_ex(tHost)[2][0]
    except Exception as e:
        print('[-]不能解析%s主机的IP，Unknown host' % tHost)
        return
    try:
        tName = gethostbyaddr(tIP)
        print('\n[+]扫描主机%s(%s):' % (tName[0], tIP))
    except Exception as e:
        print('\n[+]扫描主机%s(%s):' % (tHost, tIP))
    setdefaulttimeout(1)
    for tPort in tPorts:
        print('扫描端口' + tPort)
        # t = Thread(target=connectScan, args=(tHost, int(tPort)))
        t = Thread(target=nmapScan, args=(tIP, tPort))
        t.start()
        # connectScan(tHost, int(tPort))
        # nmapScan(tIP, tPort)


def getParser():
    """提示脚本用法，获取命令行参数并解析，
    使用全局变量传递给main函数，这样其实不好，要不就将它并入main函数吧"""
    parser = optparse.OptionParser(
        "用法：python %s -H <目标主机名> -p <目标端口>" % sys.argv[0])
    parser.add_option('-H', dest='tHost', type='string', help='目标主机名或者域名')
    parser.add_option('-p', dest='tPort', type='string', help='目标端口名，用逗号分隔')
    (options, args) = parser.parse_args()
    global tHost
    global tPorts
    tHost = options.tHost
    tPorts = str(options.tPort).split(',')
    if (tHost == None) | (tPorts[0] == None):
        print('[-]你必须输入主机名和端口!')
        print(parser.usage)
        exit(0)


def main():
    getParser()
    portScan(tHost, tPorts)


if __name__ == '__main__':
    main()
