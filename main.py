#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket
from struct import pack, unpack

class IPInfo(object):
    def __init__(self, dbname="qqwry.dat"):
        self.dbname = dbname
        with open(dbname, 'rb') as f:
            self.img = f.read()
        (self.firstIndex, self.lastIndex) = unpack('<II', self.img[:8])
        self.indexCount = int((self.lastIndex - self.firstIndex) / 7 + 1)

    def getString(self, offset=0):
        o = self.img.find(b'\0', offset)
        return self.img[offset:o].decode('gbk', 'ignore')

    def getLong3(self, offset=0):
        s = self.img[offset: offset + 3] + b'\0'
        return unpack('<I', s)[0]

    def find(self, ip):
        low = 0
        high = self.indexCount
        while low < high - 1:
            mid = low + int((high - low) / 2)
            o = self.firstIndex + mid * 7
            start_ip = unpack('<I', self.img[o: o+4])[0]
            if ip < start_ip:
                high = mid
            else:
                low = mid
        return low

    def getAddr(self, offset):
        img = self.img
        byte = img[offset]
        zone = area = ''

        if byte == 1:
            offset = self.getLong3(offset + 1)
            byte = img[offset]

        if byte == 2:
            zone_offset = self.getLong3(offset + 1)
            zone = self.getString(zone_offset)
            offset = offset + 4
        else:
            zone = self.getString(offset)
            offset += len(zone.encode('gbk', 'ignore')) + 1

        byte = img[offset]

        if byte == 2:
            area_offset = self.getLong3(offset + 1)
            area = self.getString(area_offset)
        elif byte != 1:
            area = self.getString(offset)

        return (zone, area)

    def getIPAddr(self, ip):
        ip = unpack('!I', socket.inet_aton(ip))[0]
        i = self.find(ip)
        offset = self.firstIndex + i * 7
        offset = self.getLong3(offset + 4)
        return self.getAddr(offset + 4)

    def iterate_all_ips(self):
        results = []
        for i in range(int(self.indexCount)):
            offset = self.firstIndex + i * 7
            start_ip = unpack('<I', self.img[offset: offset+4])[0]
            offset = self.getLong3(offset + 4)
            (zone, area) = self.getAddr(offset + 4)
            results.append(f'{self.long2ip(start_ip)} {zone}/{area}')
        return results

    def long2ip(self, long_ip):
        return socket.inet_ntoa(pack('!I', long_ip))

def main():
    i = IPInfo()
    all_ips_info = i.iterate_all_ips()
    with open('ip_info_output.txt', 'w', encoding='utf-8') as file:
        for info in all_ips_info:
            file.write(info + '\n')

if __name__ == '__main__':
    main()
