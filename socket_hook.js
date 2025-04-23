// 用于存储请求上下文的Map
const RequestContext = new Map();

// 用于存储域名解析结果的Map
const DnsCache = new Map();  // key: ip, value: hostname

// 生成唯一的请求ID
let requestCounter = 0;
function generateRequestId() {
    return `req_${++requestCounter}`;
}

// 请求上下文类
class NetworkRequest {
    constructor(fd, domain, type, protocol) {
        this.id = generateRequestId();
        this.fd = fd;
        this.domain = domain;
        this.type = type;
        this.protocol = protocol;
        this.timeline = [];
        this.bytesSent = 0;
        this.bytesReceived = 0;
        this.startTime = new Date();
        this.endTime = null;
        
        this.addEvent('created');
    }

    addEvent(event, details = {}) {
        this.timeline.push({
            timestamp: new Date(),
            event: event,
            details: details
        });
    }

    summarize() {
        const duration = (this.endTime || new Date()) - this.startTime;
        console.log(`\n[Request Summary] ${this.id}`);
        console.log('----------------------------------------');
        console.log(`Socket: fd=${this.fd}`);
        // 更详细的socket类型显示
        let typeStr = 'Unknown';
        switch(this.type) {
            case 1: typeStr = 'SOCK_STREAM (TCP)'; break;
            case 2: typeStr = 'SOCK_DGRAM (UDP)'; break;
            case 3: typeStr = 'SOCK_RAW'; break;
            case 4: typeStr = 'SOCK_RDM'; break;
            case 5: typeStr = 'SOCK_SEQPACKET'; break;
            case 6: typeStr = 'SOCK_DCCP'; break;
            case 10: typeStr = 'SOCK_PACKET'; break;
        }
        console.log(`Type: ${typeStr}`);
        console.log(`Duration: ${duration}ms`);
        console.log(`Bytes sent: ${this.bytesSent}`);
        console.log(`Bytes received: ${this.bytesReceived}`);
        console.log('\nTimeline:');
        this.timeline.forEach(entry => {
            const time = entry.timestamp.toLocaleTimeString('en-US', { 
                hour12: false, 
                fractionalSecondDigits: 3 
            });
            console.log(`${time} - ${entry.event}`);
            if (Object.keys(entry.details).length > 0) {
                Object.entries(entry.details).forEach(([key, value]) => {
                    console.log(`    ${key}: ${value}`);
                });
            }
        });
        console.log('----------------------------------------\n');
    }
}

const NetworkFunctions = {
    "getaddrinfo": {
        onEnter(args) {
            this.hostname = args[0].readUtf8String();
            this.service = args[1] ? args[1].readUtf8String() : null;
            this.resultPtr = args[3];  // 保存result参数的指针
            
            // console.log(`[getaddrinfo] Start resolving: ${this.hostname}`);
        },
        onLeave(retval) {
            // 检查返回值
            // console.log(`[getaddrinfo] Return value: ${retval}`);
            
            if (retval.toInt32() === 0) {  // 0 表示成功
                try {
                    const addrInfoPtr = Memory.readPointer(this.resultPtr);
                    console.log(`[getaddrinfo] Result pointer: ${addrInfoPtr}`);
                    
                    if (!addrInfoPtr.isNull()) {
                        // 读取addrinfo结构体的各个字段
                        const ai_family = Memory.readS32(addrInfoPtr.add(4));
                        const ai_socktype = Memory.readS32(addrInfoPtr.add(8));
                        const ai_protocol = Memory.readS32(addrInfoPtr.add(12));
                        const ai_addrlen = Memory.readS32(addrInfoPtr.add(16));
                        const ai_addr = Memory.readPointer(addrInfoPtr.add(24));
                        
                        console.log(`[getaddrinfo] Family: ${ai_family}, SockType: ${ai_socktype}, Protocol: ${ai_protocol}, AddrLen: ${ai_addrlen}`);
                        console.log(`[getaddrinfo] Address pointer: ${ai_addr}`);
                        
                        if (!ai_addr.isNull() && ai_family === 2) {  // AF_INET
                            const sa_family = Memory.readU16(ai_addr);
                            const port = Memory.readU16(ai_addr.add(2)).toString(16);
                            const ip1 = Memory.readU8(ai_addr.add(4));
                            const ip2 = Memory.readU8(ai_addr.add(5));
                            const ip3 = Memory.readU8(ai_addr.add(6));
                            const ip4 = Memory.readU8(ai_addr.add(7));
                            const ipAddress = `${ip1}.${ip2}.${ip3}.${ip4}`;
                            
                            console.log(`[getaddrinfo] Resolved: ${this.hostname} -> ${ipAddress}:${port}`);
                            
                            // 存储域名解析结果
                            DnsCache.set(ipAddress, this.hostname);
                        }
                    }
                } catch (e) {
                    console.log(`[getaddrinfo] Error processing result: ${e}`);
                }
            }
        }
    },
    "socket": {
        onEnter(args) {
            this.domain = args[0].toInt32();
            this.type = args[1].toInt32();
            this.protocol = args[2].toInt32();
        },
        onLeave(retval) {
            const fd = retval.toInt32();
            if (fd > 0) {
                const req = new NetworkRequest(fd, this.domain, this.type, this.protocol);
                RequestContext.set(fd, req);
            }
        }
    },

    "connect": {
        onEnter(args) {
            const fd = args[0].toInt32();
            const req = RequestContext.get(fd);
            if (req) {
                const sockaddr = args[1];
                try {
                    const sa_family = Memory.readU16(sockaddr);
                    if (sa_family === 2) { // AF_INET
                        const port = Memory.readU16(sockaddr.add(2)).toString(16);
                        const ip1 = Memory.readU8(sockaddr.add(4));
                        const ip2 = Memory.readU8(sockaddr.add(5));
                        const ip3 = Memory.readU8(sockaddr.add(6));
                        const ip4 = Memory.readU8(sockaddr.add(7));
                        const ipAddress = `${ip1}.${ip2}.${ip3}.${ip4}`;
                        
                        console.log(`[connect] Connection to ${ipAddress}:${port}`);
                        // 检查是否有对应的域名
                        const hostname = DnsCache.get(ipAddress);
                        if (hostname) {
                            console.log(`[connect] Hostname: ${hostname}`);
                        }
                        
                        req.addEvent('connect', {
                            port: parseInt(port, 16),
                            address: ipAddress,
                            hostname: hostname
                        });
                    }
                } catch (e) {
                    console.log('[connect] Error parsing sockaddr:', e);
                }
            }
        }
    },

    "send": {
        onEnter(args) {
            const fd = args[0].toInt32();
            const size = args[2].toInt32();
            const req = RequestContext.get(fd);
            if (req) {
                req.bytesSent += size;
                req.addEvent('send', { bytes: size });
                var stack="Call stack:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n");
                analyzeData(req, args[1], size,stack);
            }
        }
    },

    "recv": {
        onEnter(args) {
            this.fd = args[0].toInt32();
            this.size = args[2].toInt32();
        },
        onLeave(retval) {
            const size = retval.toInt32();
            if (size > 0) {
                const req = RequestContext.get(this.fd);
                if (req) {
                    req.bytesReceived += size;
                    req.addEvent('receive', { bytes: size });
                }
            }
        }
    },

    "close": {
        onEnter(args) {
            const fd = args[0].toInt32();
            const req = RequestContext.get(fd);
            if (req) {
                req.endTime = new Date();
                req.addEvent('closed');
                req.summarize();
                RequestContext.delete(fd);
            }
        }
    }
};

// 辅助函数：分析数据
function analyzeData(req, dataPtr, size,stack) {
    try {
        const sampleSize = Math.min(1024, size);
        const data = Memory.readByteArray(dataPtr, sampleSize);
        const bytes = new Uint8Array(data);
        
        let textCount = 0;
        let binaryCount = 0;
        
        // 统计文本和二进制字符
        for(let i = 0; i < bytes.length; i++) {
            const byte = bytes[i];
            if((byte >= 32 && byte <= 126) || byte === 10 || byte === 13) {
                textCount++;
            } else {
                binaryCount++;
            }
        }
        
        // 判断数据类型
        let dataType = 'unknown';
        if(size === 64 && bytes[0] === 8) {
            dataType = 'ICMP';
        } else if(binaryCount === 0) {
            dataType = 'text';
        } else if(binaryCount > textCount) {
            dataType = 'binary';
        } else {
            dataType = 'mixed';
        }
        
        req.addEvent('data_analysis', {
            type: dataType,
            size: size,
            sample_text_chars: textCount,
            sample_binary_chars: binaryCount
        });

        // 尝试解析数据内容并直接输出字符串
        let contents = '';

        // UTF-8 文本解析
        try {
            const utf8Content = Memory.readUtf8String(dataPtr, Math.min(size, 100));
            if (utf8Content) {
                contents += '\nUTF-8 Content:\n' + utf8Content;
            }
        } catch(e) {}
        
        // ASCII 文本解析
        try {
            const asciiContent = Memory.readCString(dataPtr, Math.min(size, 100));
            if (asciiContent) {
                contents += '\nASCII Content:\n' + asciiContent;
            }
        } catch(e) {}
        
        // 十六进制显示（简化版）
        const hexDump = Array.from(bytes.slice(0, 32))
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join(' ');
        if (hexDump) {
            contents += '\nHex Dump (first 32 bytes):\n' + hexDump;
        }

        // 记录解析结果
        req.addEvent('data_content', {
            data_type: dataType,
            sample_size: sampleSize,
            total_size: size,
            contents: contents || '(No readable content)',
            stack:stack
        });

    } catch(e) {
        console.log('Error analyzing data:', e);
        req.addEvent('data_content', {
            error: e.toString()
        });
    }
}

// 开始hook所有网络相关函数
for(const [funcName, handlers] of Object.entries(NetworkFunctions)) {
    const address = Module.findExportByName(null, funcName);
    if(address) {
        Interceptor.attach(address, handlers);
        console.log(`[*] Hooked ${funcName}`);
    }
}