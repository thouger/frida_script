let Adjust = Java.use("com.adjust.sdk.Adjust");
Adjust["setTestOptions"].implementation = function (adjustTestOptions) {
    console.log(`Adjust.setTestOptions is called: adjustTestOptions=${adjustTestOptions}`);
    this["setTestOptions"](adjustTestOptions);
};