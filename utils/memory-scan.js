
function main() {
		var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
		var range;
		function processNext(){
			range = ranges.pop();
			if(!range){
				// we are done
				return;
			}
			// due to the lack of blacklisting in Frida, there will be
			// always an extra match of the given pattern (if found) because
			// the search is done also in the memory owned by Frida.
			Memory.scan(range.base, range.size, '78 33 55 7e', {
				onMatch: function(address, size){
						console.log('[+] Pattern found at: ' + address.toString());
					},
				onError: function(reason){
						console.log('[!] There was an error scanning memory:'+reason);
					},
				onComplete: function(){
						processNext();
					}
				});
		}
		processNext();
}

setTimeout(main, 0)