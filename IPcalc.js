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

function IpCalc() {
  this.v4 = (ipOrNet, intMask = false) => {
    let ipSplit = []
    if (intMask == false) ipSplit = ipOrNet.split('/')
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
  	const part1 = ip.split("/")[0]
    if (this.v4Verify(part1)) return part1
    else return false
  }
  this.v4Clean = (ip) => {
  	return this.v4Long2Ip(this.v4Ip2Long(ip))
  }
  this.v4ArpaZone = (ip) => {
  	if (!this.v4Verify(ip)) return false
  	const ipSplit = ip.split(".")
    if (ipSplit.length != 4) return false
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
