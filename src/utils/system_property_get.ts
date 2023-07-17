//@ts-nocheck
Interceptor.attach(Module.findExportByName(null, '__system_property_get'), {
	onEnter: function (args) {
		this._name = args[0].readCString();
		this._value = args[1];
	},
	onLeave: function (retval) {
		console.log(JSON.stringify({
			result_length: retval,
			name: this._name,
			val: this._value.readCString()
		}));
	}
});