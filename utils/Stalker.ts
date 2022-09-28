//@ts-nocheck

// var app = new ModuleMap(isAppAddress);

// Process.enumerateThreadsSync().forEach(function(thread){
//     Stalker.follow(thread.id,{
//         transform: function (iterator) {
//             var instruction = iterator.next();
//             if (!app.has(instruction.address)) {
//                 do{
//                     iterator.keep();
//                 }  while ((iterator.next()) !== null);
//                 return ;
//             }

//             iterator.putCallout((context) => {
//                 console.log(JSON.stringify(context))
//               })

//             do{
//                 console.log(instruction.address + ":" + instruction);
//                 iterator.keep();
//             }  while ((instruction = iterator.next()) !== null);
//         }
//     })
// })

// function isAppAddress(module) {
//     // console.log(module.path)
//     return module.path.indexOf("liblimited-jni-spotify.so") != -1;
// }





/////////////////////////////
// const mainThread = Process.enumerateThreads()[0];

// Stalker.follow(mainThread.id, {
//   events: {
//     call: true, // 调用指令

//     // 其他事件:
//     ret: false, // 返回指令
//     exec: false, // 全部指令:不推荐, 因为数据量过大
//     block: false, // 已计算的块: 粗略执行轨迹
//     compile: false // 已编译的块: 对覆盖率很有用
//   },

  //
  // 仅指定以下两个回调之一. (见下方的备注.)
  //

  //
  // onReceive: 伴随 `events` 一起被调用. `events` 包含一个或多个
  //            GumEvent 结构. 关于格式的细节请参考 `gumevent.h`
  //            您需要使用 `Stalker.parse()` 来解释其中的数据.
  //
  //onReceive: function (events) {
  //},
  //

  //
  // onCallSummary: 伴随 `summary` 一起被调用. `summary` 是一个由调用的
  //                对象地址作为键, 当前时间窗口内调用次数为值构成的键值对对象.
  //                通常情况下您应当实现这个方法而不是 `onReceive()`, 例如:
  //                当您只想知道哪些目标被调用, 以及被调用了多少次, 但不关心
  //                调用的顺序时.
  //
//   onCallSummary: function (summary) {
//   },

  //
  // 进阶用例:  这里展示了您应当如何插入您自己的 StalkerTransformer.
  //            您所提供的方法将在 Stalker 想要重新编译即将被已跟踪的线程
  //            执行的一个基础代码块时被同步调用.
  //
  //transform: function (iterator) {
  //  var instruction = iterator.next();
  //
  //  var startAddress = instruction.address;
  //  var isAppCode = startAddress.compare(appStart) >= 0 &&
  //      startAddress.compare(appEnd) === -1;
  //
  //  do {
  //    if (isAppCode && instruction.mnemonic === 'ret') {
  //      iterator.putCmpRegI32('eax', 60);
  //      iterator.putJccShortLabel('jb', 'nope', 'no-hint');
  //
  //      iterator.putCmpRegI32('eax', 90);
  //      iterator.putJccShortLabel('ja', 'nope', 'no-hint');
  //
  //      iterator.putCallout(onMatch);
  //
  //      iterator.putLabel('nope');
  //    }
  //
  //    iterator.keep();
  //  } while ((instruction = iterator.next()) !== null);
  //},
  //
  // 默认的实现为:
  //
  //   while (iterator.next() !== null)
  //     iterator.keep();
  //
  // 上面的示例展示了您可以插入您自己的代码到应用内存范围内被跟踪的线程的
  // 每一个 `ret` 指令前. 它插入的代码检查了 `eax` 寄存器是否包含一个 60
  // 到 90 之间的值, 并插入了一个同步的回调, 每当出现这种情况时便调用 JavaScript
  // 回调. 这个回调接受一个参数, 这个参数给与您接触 CPU 寄存器, 并修改它
  // 的值的能力.
  //
  // function onMatch (context) {
  //   console.log('Match! pc=' + context.pc +
  //       ' rax=' + context.rax.toInt32());
  // }
  //
  // 请注意, 不调用 keep() 将导致指令被遗弃, 这使得您在必要时完全替换特定的
  // 指令成为了可能.
  //

  //
  // 想要更好的性能? 试着在 C 中书写回调:
  //
  // /*
  //  * const cm = new CModule(\`
  //  *
  //  * #include <gum/gumstalker.h>
  //  *
  //  * static void on_ret (GumCpuContext * cpu_context,
  //  *     gpointer user_data);
  //  *
  //  * void
  //  * transform (GumStalkerIterator * iterator,
  //  *            GumStalkerWriter * output,
  //  *            gpointer user_data)
  //  * {
  //  *   cs_insn * insn;
  //  *
  //  *   while (gum_stalker_iterator_next (iterator, &insn))
  //  *   {
  //  *     if (insn->id == X86_INS_RET)
  //  *     {
  //  *       gum_x86_writer_put_nop (output);
  //  *       gum_stalker_iterator_put_callout (iterator,
  //  *           on_ret, NULL, NULL);
  //  *     }
  //  *
  //  *     gum_stalker_iterator_keep (iterator);
  //  *   }
  //  * }
  //  *
  //  * static void
  //  * on_ret (GumCpuContext * cpu_context,
  //  *         gpointer user_data)
  //  * {
  //  *   printf ("on_ret!\n");
  //  * }
  //  *
  //  * `);
  //  */
  //
  //transform: cm.transform,
  //data: ptr(1337) /* user_data */
  //
  // 您也可以使用一个混合的方案, 并且只在 C 中书写部分回调.
  //
// });


var modules = Process.enumerateModules();

modules.forEach(module => {
    console.log(module.name, module.base, module.size);
});

modules.forEach(module => {
    if (module.name.indexOf("liblimited-jni-spotify.so") === -1){

        console.log(`Excluding ${module.name}`);

        // We're only interested in stalking our code
        Stalker.exclude({
            "base": module.base,
            "size": module.size
        });
    }
});

Process.enumerateThreadsSync().map(t => {
    console.log(`Thread id is ${t.id}`);

    Stalker.follow(t.id, {
        transform(iterator) {
            console.log("HERE")
            var instruction = iterator.next()
            do {
                console.log(instruction);
                iterator.keep()
            } while ((instruction = iterator.next()) !== null)
        }
    });
});

////////////////////////////////////

// var app = new ModuleMap(isAppAddress);

// Process.enumerateThreadsSync().forEach(function(thread){
//     Stalker.follow(thread.id,{
//         transform: function (iterator) {
//             var instruction = iterator.next();
//             if (!app.has(instruction.address)) {
//                 do{
//                     iterator.keep();
//                 }  while ((iterator.next()) !== null);
//                 return ;
//             }

//             iterator.putCallout((context) => {
//                 console.log(JSON.stringify(context))
//               })

//             do{
//                 console.log(instruction.address + ":" + instruction);
//                 iterator.keep();
//             }  while ((instruction = iterator.next()) !== null);
//         }
//     })
// })

// function isAppAddress(module) {
//     // console.log(module.path)
//     return module.path.indexOf("liblimited-jni-spotify.so") != -1;
// }