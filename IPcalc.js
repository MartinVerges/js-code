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

// Example:
// const calc = new IpCalc();
// document.write("MAIN = " + JSON.stringify( calc.v4("192.168.0.22/24") ) + "<br>")

function IpCalc() {
  this.v4 = function(cidrip) {
    const ipSplit = cidrip.split("/");
    return {
      'address': ipSplit[0],
      'gateway': this.v4AddValue(this.v4GetNetwork(ipSplit[0], ipSplit[1]), 1),
      'netmask': this.v4GetNask(ipSplit[1]),
      'cidrmask': ipSplit[1],
      'network': this.v4GetNetwork(ipSplit[0], ipSplit[1]),
      'hostmin': this.v4AddValue(this.v4GetNetwork(ipSplit[0], ipSplit[1]), 2),
      'hostmax': this.v4AddValue(this.v4GetBroadcast(ipSplit[0], ipSplit[1]), -1),
      'broadcast': this.v4GetBroadcast(ipSplit[0], ipSplit[1]),
      'hostcount': this.v4Count(ipSplit[1])
    }
  }

  this.v4Count = function(intMask) {
    if( intMask < 1 || intMask > 32) return false
    return 1 << (32 - intMask)
  }

  this.v4GetBroadcast = function(ip, intMask) {
    if( intMask < 1 || intMask > 32) return false
    return this.v4Long2Ip( this.v4Ip2Long(ip) | ~(0xffffffff << (32 - intMask)) & 0xffffffff )
  }

  this.v4GetNetwork = function(ip, intMask) {
    if( intMask < 1 || intMask > 32) return false
    return this.v4Long2Ip( this.v4Ip2Long(ip) & (0xffffffff << (32 - intMask)) )
  }

  this.v4GetNask = function(intMask) {
    if( intMask < 1 || intMask > 32) return false
    return this.v4Long2Ip( 0xffffffff << (32 - intMask))
  }

  this.v4AddValue = function(ip, add) {
    return this.v4Long2Ip( this.v4Ip2Long(ip) + add)
  }

  this.v4Ip2Long = function(ip) {
    const ipSplit = ip.match(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/i)
    if( typeof ipSplit == undefined ) return false
    return ipSplit[1] * (ipSplit[0] === 1 || 16777216) + ipSplit[2] * (ipSplit[0] <= 2 || 65536) + ipSplit[3] * (ipSplit[0] <= 3 || 256) + ipSplit[4] * 1
  }
  this.v4Long2Ip = function(ip) {
    return [ip >>> 24, ip >>> 16 & 0xFF, ip >>> 8 & 0xFF, ip & 0xFF].join('.')
  }
}
