/***************************************************************************
Copyright (c) 2016, Martin Verges <martin@verges.cc>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.
  
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
***************************************************************************/

// Usage Help:
// -----------
// const calc = new IpCalc();
// calc.v4("192.168.0.0/24") || calc.v4("192.168.0.0", "24") = { "address": "192.168.0.0", "gateway": "192.168.0.1", "netmask": "255.255.255.0", "cidrmask": "24", "network": "192.168.0.0", "hostmin": "192.168.0.2", "hostmax": "192.168.0.254", "broadcast": "192.168.0.255", "hostcount": 256 }
// calc.v4Distance("192.168.0.0", "192.168.0.10") = 10
// calc.v4ArpaZone("192.168.0.0") = 0.168.192.in-addr.arpa
// calc.v4Clean('192.168.000.001') = 192.168.0.1
// calc.v4GetDecMask('255.255.255.0') = 24
// calc.v4IpFromCIDR('192.168.0.22/24') = 192.168.0.22
// calc.v4Verify('192.168.0.0') = true || calc.v4Verify('392.168.0.0') = false
// calc.v4InSubnet('192.168.0.0/24', '192.168.0.5') == true || calc.v4InSubnet('192.168.0.0/24', '192.168.1.5') == false
// calc.v4ListAddresses('192.168.0.0', '192.168.0.5') == 192.168.0.0,192.168.0.1,192.168.0.2,...5
//
// and with IPv6
//
// calc.v6('2001:0db8:85a3:08d3:1319:8a2e:0370:7347/64') = { "address": "2001:db8:85a3:8d3:1319:8a2e:370:7347", "network": "2001:0db8:85a3:08d3::", "gateway": "2001:0db8:85a3:08d3::1", "fullIP": 2001:0db8:85a3:08d3:1319:8a2e:0370:7347", "arpa": "3.d.8.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa", "cidrmask": 64 }
// calc.v6ArpaZone('2001:0db8:85a3:08d3::', 64) = 3.d.8.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa
// calc.v6Full('ff:a:b:c::12') = 00ff:000a:000b:000c:0000:0000:0000:0012
// calc.v6Short('00ff:000a:000b:000c:0000:0000:0000:0012') = ff:a:b:c::12
// calc.v6Verify('ff:a:b:c::12') = true || calc.v6Verify('hello, world') = false
// calc.v6ToBlocks('ff:a:b:c::12') = [ "00ff", "000a", "000b", "000c", "0000", "0000", "0000", "0012" ]
// calc.v6GetNetwork('2001:0db8:85a3:08d3:1319:8a2e:0370:7347', 64) = "2001:0db8:85a3:08d3::"
// calc.v6Gateway('2001:0db8:85a3:08d3:1319:8a2e:0370:7347', 64) = "2001:0db8:85a3:08d3::1"
//

function IpCalc () {
  this.v6 = (ipOrNet, intMask = false) => {
    let ipSplit = []
    if (intMask === false) ipSplit = ipOrNet.split('/')
    else ipSplit = [ipOrNet, intMask]
    ipSplit[1] = parseInt(ipSplit[1])

    return this.v6Verify(ipSplit[0]) ? {
      'address': this.v6Short(ipSplit[0]),
      'network': this.v6GetNetwork(ipSplit[0], ipSplit[1]),
      'gateway': this.v6Gateway(ipSplit[0], ipSplit[1]),
      'fullIP': this.v6Full(ipSplit[0]),
      'arpa': this.v6ArpaZone(ipSplit[0], ipSplit[1]),
      'cidrmask': ipSplit[1]
    } : false
  }

  this.v6Gateway = (ip, intMask) => {
    return this.v6GetNetwork(ip, intMask).replace(/::$/, '::1')
  }
  this.v6GetNetwork = (ip, intMask) => {
    if (!this.v6Verify(ip)) return false
    if (intMask < 1 || intMask > 128) return false

    let v6Blocks = this.v6ToBlocks(ip)
    for (let index = 7; index >= 0; index--) { // each 16 bits starting from end
      if (intMask >= 16) {
        v6Blocks[index] = '0'
        intMask -= 16
      } else if (intMask > 0) {
        v6Blocks[index] = (this.hexdec(v6Blocks[index]) & (0xffff << (16 - intMask))).toString(16)
        break
      } else break
    }
    return v6Blocks.join(':').replace(/:0(:0)+:/, '::').replace(/::0$/, '::')
  }
  this.v6ArpaZone = (ip, intMask) => {
    if (!this.v6Verify(ip)) return false
    if (intMask === 16 || intMask === 32 || intMask === 48 || intMask === 64 || intMask === 80 || intMask === 96 || intMask === 112) {
      const fullstring = this.v6ToBlocks(this.v6GetNetwork(ip, intMask)).join('').replace(/0+$/, '')
      return this.strrev(fullstring).split('').join('.') + '.ip6.arpa'
    } else {
      // Split into multiple full blocks (/29 == 8x /32)
      // FIXME: todo
      // let zoneList = []
      return 'Sorry, not yet implemented'
    }
  }
  this.v6Full = (ip) => {
    if (!this.v6Verify(ip)) return false
    return this.v6ToBlocks(ip).join(':')
  }
  this.v6Short = (ip) => {
    if (!this.v6Verify(ip)) return false
    let shortIP = this.v6ToBlocks(ip, true).join(':')
    return shortIP.replace(/:0(:0)+:/, '::')
  }
  this.v6ToBlocks = (ip, trimmed = false) => {
    if (!this.v6Verify(ip)) return false
    let v6Blocks = new Array(8)
    ip = ip.toLowerCase()
    if (ip.includes('::')) {
      const ipSplit = ip.split('::')
      if (ipSplit.length === 2) {
        const left2right = ipSplit[0].split(':')
        const right2left = ipSplit[1].split(':').reverse()
        for (let index = 0; index < left2right.length; ++index) v6Blocks[index] = left2right[index]
        for (let index = 0; index < right2left.length; ++index) v6Blocks[8 - index] = right2left[index]
      } else return false
    } else {
      const left2right = ip.split(':')
      for (let index = 0; index < left2right.length; ++index) v6Blocks[index] = left2right[index]
    }
    if (trimmed === true) {
      for (let index = 0; index < 8; ++index) {
        v6Blocks[index] = this.trimLeft(v6Blocks[index], '0') || '0'
      }
    } else {
      for (let index = 0; index < 8; ++index) v6Blocks[index] = this.padLeft(v6Blocks[index], 4)
    }
    return v6Blocks
  }
  this.v6Verify = (ip) => {
    return /^(([0-9a-f]{1,4}:){7,7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:)|fe80:(:[0-9a-f]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-f]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/i.test(ip)
  }
  // Helpers for IPv6
  this.strrev = (s) => {
    return s.split('').reverse().join('')
  }
  this.trimLeft = (fullString, charList = '\\s') => {
    if (typeof fullString === 'undefined') fullString = ''
    if (typeof fullString !== 'string') fullString = String(fullString)
    return String(fullString).replace(new RegExp('^[' + charList + ']+', 'g'), '')
  }
  this.padLeft = (n, width, z = '0') => {
    if (typeof n === 'undefined') n = ''
    if (typeof n !== 'string') n = String(n)
    return n.length >= width ? n : new Array(width - n.length + 1).join(z) + n
  }
  this.hexdec = (hexString) => {
    hexString = String(hexString).replace(/[^a-f0-9]/gi, '')
    return parseInt(hexString, 16)
  }

  this.v4 = (ipOrNet, intMask = false) => {
    let ipSplit = []
    if (intMask === false) ipSplit = ipOrNet.split('/')
    else ipSplit = [ipOrNet, intMask]

    return this.v4Verify(ipSplit[0]) ? {
      'address': ipSplit[0],
      'gateway': this.v4AddValue(this.v4GetNetwork(ipSplit[0], ipSplit[1]), 1),
      'netmask': this.v4GetDotMask(ipSplit[1]),
      'cidrmask': ipSplit[1],
      'network': this.v4GetNetwork(ipSplit[0], ipSplit[1]),
      'hostmin': this.v4AddValue(this.v4GetNetwork(ipSplit[0], ipSplit[1]), 2),
      'hostmax': this.v4AddValue(this.v4GetBroadcast(ipSplit[0], ipSplit[1]), -1),
      'broadcast': this.v4GetBroadcast(ipSplit[0], ipSplit[1]),
      'hostcount': this.v4Count(ipSplit[1])
    } : false
  }
  this.v4ListAddresses = (lowerIP, higherIP) => {
    if (!this.v4Verify(lowerIP) || !this.v4Verify(higherIP)) return false
    let low = this.v4Ip2Long(lowerIP)
    const high = this.v4Ip2Long(higherIP)
    let outArray = []
    while (low <= high) {
      outArray.push(this.v4Long2Ip(low))
      low++
    }
    return outArray
  }
  this.v4Verify = (ip) => {
    return /^((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$/.test(ip)
  }
  this.v4IpFromCIDR = (ip) => {
    const part1 = ip.split('/')[0]
    if (this.v4Verify(part1)) return part1
    else return false
  }
  this.v4Clean = (ip) => {
    return this.v4Long2Ip(this.v4Ip2Long(ip))
  }
  this.v4ArpaZone = (ip) => {
    if (!this.v4Verify(ip)) return false
    const ipSplit = ip.split('.')
    if (ipSplit.length !== 4) return false
    return ipSplit[2] + '.' + ipSplit[1] + '.' + ipSplit[0] + '.in-addr.arpa'
  }
  this.v4Tov6 = (ip) => {
    if (!this.v4Verify(ip)) return false
    return '::ffff:' + ip
  }
  this.v4Distance = (ip1, ip2) => {
    if (!this.v4Verify(ip1) || !this.v4Verify(ip2)) return false
    const intVal1 = this.v4Ip2Long(ip1)
    const intVal2 = this.v4Ip2Long(ip2)
    if (intVal1 > intVal2) return intVal1 - intVal2
    else return intVal2 - intVal1
  }
  this.v4Count = (intMask) => {
    if (intMask < 1 || intMask > 32) return false
    return 1 << (32 - intMask)
  }
  this.v4GetBroadcast = (ip, intMask) => {
    if (!this.v4Verify(ip)) return false
    if (intMask < 1 || intMask > 32) return false
    return this.v4Long2Ip(this.v4Ip2Long(ip) | ~(0xffffffff << (32 - intMask)) & 0xffffffff)
  }
  this.v4GetNetwork = (ip, intMask) => {
    if (!this.v4Verify(ip)) return false
    if (intMask < 1 || intMask > 32) return false
    return this.v4Long2Ip(this.v4Ip2Long(ip) & (0xffffffff << (32 - intMask)))
  }
  this.v4GetDecMask = (stringMask) => {
    const binVal = parseInt(this.v4Ip2Long(stringMask), 10).toString(2)
    return binVal.match(/([10]*?)0*$/)[1].length
  }
  this.v4GetDotMask = (intMask) => {
    if (intMask < 1 || intMask > 32) return false
    return this.v4Long2Ip(0xffffffff << (32 - intMask))
  }
  this.v4AddValue = (ip, add) => {
    if (!this.v4Verify(ip)) return false
    return this.v4Long2Ip(this.v4Ip2Long(ip) + add)
  }
  this.v4Ip2Long = (ip) => {
    const ipSplit = ip.match(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/)
    if (typeof ipSplit === undefined) return false
    return ipSplit[1] * (ipSplit[0] === 1 || 16777216) + ipSplit[2] * (ipSplit[0] <= 2 || 65536) + ipSplit[3] * (ipSplit[0] <= 3 || 256) + ipSplit[4] * 1
  }
  this.v4Long2Ip = (longIp) => {
    return [longIp >>> 24, longIp >>> 16 & 0xFF, longIp >>> 8 & 0xFF, longIp & 0xFF].join('.')
  }
  this.v4InSubnet = (cidrip, ip) => {
    const ipSplit = cidrip.split('/')
    return this.v4Ip2Long(this.v4GetNetwork(ipSplit[0], ipSplit[1])) <= this.v4Ip2Long(ip) && this.v4Ip2Long(this.v4(cidrip).hostmax) >= this.v4Ip2Long(ip)
  }
}
