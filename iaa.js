Java.perform(function() {
    var targetClass = Java.use('com.ironsource.f5');
    
    // 按竞价ID跟踪每次竞价的信息
    let auctionBids = {};

    // hook a函数的所有重载
    var overloadCount = targetClass.a.overloads.length;
    for (var i = 0; i < overloadCount; i++) {
        targetClass.a.overloads[i].implementation = function() {
            try {
                var retval = this.a.apply(this, arguments);
                console.log('a() 返回值:', retval);
                return retval;
            } catch(e) {
                return this.a.apply(this, arguments);
            }
        }
    }                   
    
    // Hook构造函数的所有重载
    var overloadCount = targetClass.$init.overloads.length;

    for (var i = 0; i < overloadCount; i++) {
        console.log('Hooking $init() at index:', i);
        targetClass.$init.overloads[i].implementation = function() {
            try {
                let jsonStr = arguments[0].toString();
                if (jsonStr) {
                    let jsonData1 = JSON.parse(jsonStr);
                    let logMessage = '';

                    // 检查两种可能的数据格式
                    const adNetwork = jsonData1.armData?.adNetwork || 
                                    (jsonData1.instance ? jsonData1.instance.split('_')[0] : null);
                    
                    if (!adNetwork) return this.$init.apply(this, arguments);

                    let auctionId = '';
                    if (arguments[2]) {
                        try {
                            let jsonData2 = JSON.parse(arguments[2].toString());
                            auctionId = jsonData2.auctionId;
                        } catch (err) {
                            console.log('解析广告详情错误:', err);
                            return this.$init.apply(this, arguments);
                        }
                    }
            
                    if (!auctionId) {
                        console.log('无效的竞价ID');
                        return this.$init.apply(this, arguments);
                    }
            
                    if (!auctionBids[auctionId]) {
                        auctionBids[auctionId] = {
                            networks: {},
                        };
                    }
            
                    auctionBids[auctionId].networks[adNetwork] = (auctionBids[auctionId].networks[adNetwork] || 0) + 1;
            
                    // 检查两种可能的竞价胜出格式
                    const isWinningBid = (jsonData1.adSets && 
                                        jsonData1.adSets[0] && 
                                        jsonData1.adSets[0].isAuctionClosed === true) ||
                                       (jsonData1.adMarkup && 
                                        JSON.parse(jsonData1.adMarkup).adSets?.[0]?.isAuctionClosed === true);
            
                    // 拼接竞价信息
                    logMessage += `\n[竞价信息 - ID: ${auctionId}]\n`;
                    logMessage += `   广告网络: ${adNetwork}\n`;

                    // 处理两种不同的数据格式
                    if (jsonData1.armData) {
                        logMessage += `   实例名称: ${jsonData1.armData.instanceName}\n`;
                        logMessage += `   实例ID: ${jsonData1.armData.instanceId}\n`;
                        logMessage += `   价格: ${jsonData1.price}\n`;
                        logMessage += `   收益: ${jsonData1.armData.revenue}\n`;
                        logMessage += `   终身收益: ${jsonData1.armData.lifetimeRevenue}\n`;
                        logMessage += `   精度类型: ${jsonData1.armData.precision}\n`;
                    } else if (jsonData1.instance) {
                        const adMarkup = JSON.parse(jsonData1.adMarkup);
                        logMessage += `   实例名称: ${jsonData1.instance}\n`;
                        logMessage += `   请求ID: ${adMarkup.requestId}\n`;
                        logMessage += `   广告位ID: ${adMarkup.placementId}\n`;
                    }

                    logMessage += `   当前竞价次数: ${arguments[1]}\n`;

                    // 拼接广告详情
                    if (arguments[2]) {
                        let jsonData2 = JSON.parse(arguments[2].toString());
                        logMessage += `   广告单元: ${jsonData2.adUnit}\n`;
                        logMessage += `   国家: ${jsonData2.country}\n`;
                        logMessage += `   格式: ${jsonData2.adFormat}\n`;
                        logMessage += `   中介单元名称: ${jsonData2.mediationAdUnitName}\n`;
                        logMessage += `   中介ID: ${jsonData2.mediationAdUnitId}\n`;
                    }
                    
                    // 添加广告集信息
                    const adSets = jsonData1.adSets || 
                                 (jsonData1.adMarkup ? JSON.parse(jsonData1.adMarkup).adSets : null);
                    
                    // adSets还有一些其他的信息，这里只是简单的输出了一些
                    if (adSets && adSets[0]) {
                        const adSet = adSets[0];
                        logMessage += `   过期时间: ${adSet.expiry}秒\n`;
                        logMessage += `   竞价是否关闭: ${adSet.isAuctionClosed}\n`;
                        
                        // 添加具体广告信息
                        if(adSet.ads && adSet.ads[0]) {
                            const ad = adSet.ads[0];
                            logMessage += `   广告创意ID: ${ad.creativeId || ''}\n`;
                            logMessage += `   展示ID: ${ad.impressionId || ''}\n`;
                            logMessage += `   广告类型: ${ad.metaInfo?.creativeType || ''}\n`;
                            
                            // 添加宏变量信息
                            if(ad.metaInfo?.omsdkInfo?.macros) {
                                const macros = ad.metaInfo.omsdkInfo.macros;
                                logMessage += `   设备信息: ${macros.$HANDSET_MAKE || ''} ${macros.$HANDSET_NAME || ''}\n`;
                                logMessage += `   广告位尺寸: ${macros.$PLACEMENT_DIMENSION || ''}\n`;
                                logMessage += `   地理位置: ${macros.$GEO_CC || ''} (${macros.$GEO_LAT || ''}, ${macros.$GEO_LNG || ''})\n`;
                            }
                        }
                    }

                    logMessage += `   参数0: ${arguments[0]}\n`;
            
                    // 如果是胜出的广告
                    if (isWinningBid) {
                        logMessage += '\n[胜出广告详情]\n';
                        logMessage += `\n[竞价统计 - ID: ${auctionId}]\n`;
                        Object.entries(auctionBids[auctionId].networks).forEach(([network, count]) => {
                            logMessage += `   ${network}: ${count}次竞价\n`;
                        });
            
                        // 清理该竞价ID的数据
                        delete auctionBids[auctionId];
                    }
            
                    // 输出日志
                    console.log(logMessage);
                }
                
                return this.$init.apply(this, arguments);
                
            } catch(e) {
                console.log('Error:', e);
                console.log(arguments[2]);
                return this.$init.apply(this, arguments);
            }
        }
    }
});